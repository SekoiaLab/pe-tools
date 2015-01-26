'''
Created on 23 avr. 2014

@author: Christophe
'''

import struct
#import peparser
from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits
import pcodes


def getVbHeaderAddress(pe):
    '''
    Test if the given PE is has a VB header.
    '''
    offset = pe.optionalHeader.AddressOfEntryPoint
    imageBase = pe.optionalHeader.ImageBase
    instr = Decode(offset, pe.mapped[offset:offset+5], Decode32Bits)[0]
    #print "0x%08x (%02x) %-20s %s" % (instr[0], instr[1], instr[3], instr[2])
    if 'PUSH' in instr[2]:
        # convert from base 16
        vb_header = int(instr[2].split()[2], 0) - pe.optionalHeader.ImageBase
        # next instruction
        offset += 5
        instr = Decode(offset, pe.mapped[offset:offset+5], Decode32Bits)[0]
        if 'CALL' in instr[2]:
            # follow the EIP register
            offset = int(instr[2].split()[1], 0)
            instr = Decode(offset, pe.mapped[offset:offset+6], Decode32Bits)[0]
            if 'JMP' in instr[2]:
                offset = int(instr[2].split()[2].strip("[]"), 0) - imageBase
                for import_descr in pe.Imports:
                    if import_descr.Name == 'MSVBVM60.DLL' and import_descr.Thunk == offset:
                        return vb_header
    return None

# vb_header Structure
class VbParser(object):

    def __init__(self, pe, offset):
        self.pe = pe
        self.offset = offset
        self._unpack(self.pe.mapped)
        if self.Signature != 'VB5!':
            print 'INVALID VB HEADER: ', str(self.Signature)
        else:
            self.projectInfo = ProjectInfo(self.pe, self.aProjectInfo - self.pe.optionalHeader.ImageBase)

    def _unpack(self, data):
        header_struct = struct.unpack("<4sH14s14sHLLLLLLLLHHLLLLLLLL", data[self.offset:self.offset+104])
        self.Signature               = header_struct[0]
        self.RuntimeBuild            = header_struct[1]
        self.LanguageDLL             = header_struct[2]
        self.BackupLanguageDLL       = header_struct[3]
        self.RuntimeDLLVersion       = header_struct[4]
        self.LanguageID              = header_struct[5]
        self.BackupLanguageID        = header_struct[6]
        self.aSubMain                = header_struct[7]
        self.aProjectInfo            = header_struct[8]
        self.fMDLIntObjs             = header_struct[9]
        self.fMDLIntObjs2            = header_struct[10]
        self.ThreadFlags             = header_struct[11]
        self.ThreadCount             = header_struct[12]
        self.FormCount               = header_struct[13]
        self.ExternalComponentCount  = header_struct[14]
        self.ThunkCount              = header_struct[15]
        self.aGUITable               = header_struct[16]
        self.aExternalComponentTable = header_struct[17]
        self.aComRegisterData        = header_struct[18]
        # get C string starting at offset header_struct[19]
        offset = self.offset+ header_struct[19]
        end = data[offset:].find('\0')
        self.oProjectExename = data[offset:offset+end]
        # get C string starting at offset header_struct[20]
        offset = self.offset+ header_struct[20]
        end = data[offset:].find('\0')
        self.oProjectTitle   = data[offset:offset+end]
        # get C string starting at offset header_struct[21]
        offset = self.offset+ header_struct[21]
        end = data[offset:].find('\0')
        self.oHelpFile       = data[offset:offset+end]
        # get C string starting at offset header_struct[22]
        offset = self.offset+ header_struct[22]
        end = data[offset:].find('\0')
        self.oProjectName    = data[offset:offset+end]

    def __str__(self):
        output = 'VB HEADER:\n----------\n'
        output += 'Signature              : ' + self.Signature + '\n'
        output += 'RuntimeBuild           : ' + str(self.RuntimeBuild) + '\n'
        output += 'LanguageDLL            : ' + self.LanguageDLL + '\n'
        output += 'BackupLanguageDLL      : ' + self.BackupLanguageDLL + '\n'
        output += 'RuntimeDLLVersion      : ' + str(self.RuntimeDLLVersion) + '\n'
        output += 'LanguageID             : ' + str(self.LanguageID) + '\n'
        output += 'BackupLanguageID       : ' + str(self.BackupLanguageID) + '\n'
        output += 'aSubMain               : ' + hex(self.aSubMain) + '\n'
        output += 'aProjectInfo           : ' + hex(self.aProjectInfo) + '\n'
        output += 'fMDLIntObjs            : ' + hex(self.fMDLIntObjs) + '\n'
        output += 'fMDLIntObjs2           : ' + hex(self.fMDLIntObjs2) + '\n'
        output += 'ThreadFlags            : ' + hex(self.ThreadFlags) + '\n'
        output += 'ThreadCount            : ' + str(self.ThreadCount) + '\n'
        output += 'FormCount              : ' + str(self.FormCount) + '\n'
        output += 'ExternalComponentCount : ' + str(self.ExternalComponentCount) + '\n'
        output += 'ThunkCount             : ' + str(self.ThunkCount) + '\n'
        output += 'aGUITable              : ' + hex(self.aGUITable) + '\n'
        output += 'aExternalComponentTable: ' + hex(self.aExternalComponentTable) + '\n'
        output += 'aComRegisterData       : ' + hex(self.aComRegisterData) + '\n'
        output += 'oProjectExename        : ' + self.oProjectExename + '\n'
        output += 'oProjectTitle          : ' + self.oProjectTitle + '\n'
        output += 'oHelpFile              : ' + self.oHelpFile + '\n'
        output += 'oProjectName           : ' + self.oProjectName + '\n\n'
        output += self.projectInfo.__str__()
        return output


# ProjectInfo structure
class ProjectInfo(object):
    
    def __init__(self, pe, offset):
        self.offset = offset
        self._unpack(pe.mapped)
        self.objectTable = ObjectTable(pe, self.aObjectTable - pe.optionalHeader.ImageBase)

    def _unpack(self, data):
        header_struct = struct.unpack("<LLLLLLLLL528sLL", data[self.offset:self.offset+572])
        self.lTemplateVersion     = header_struct[0]  # VB compatible version
        self.aObjectTable         = header_struct[1]  # Pointer to ObjectTable
        self.lNull1               = header_struct[2]  #
        self.aStartOfCode         = header_struct[3]  # Pointer to the start of some Assembly listing
        self.aEndOfCode           = header_struct[4]  # Pointer to the end of some Assembly listing
        self.lDataBufferSize      = header_struct[5]  # Size of Data Buffer
        self.aThreadSpace         = header_struct[6]  #
        self.aVBAExceptionhandler = header_struct[7]  # Pointer to VBA Exception Handler
        self.aNativeCode          = header_struct[8]  # Pointer to the start of RAW Native Code
        self.IdentifierStr_char   = header_struct[9]  #
        self.aExternalTable       = header_struct[10] # Pointer to API Imports Table
        self.lExternalCount       = header_struct[11] # Number of API's imported

    def __str__(self):
        output =  'ProjectInfo:\n----------\n'
        output += 'lTemplateVersion    : ' + hex(self.lTemplateVersion) + '\n'
        output += 'aObjectTable        : ' + hex(self.aObjectTable) + '\n'
        output += 'lNull1              : ' + hex(self.lNull1) + '\n'
        output += 'aStartOfCode        : ' + hex(self.aStartOfCode) + '\n'
        output += 'aEndOfCode          : ' + hex(self.aEndOfCode) + '\n'
        output += 'lDataBufferSize     : ' + hex(self.lDataBufferSize) + '\n'
        output += 'aThreadSpace        : ' + hex(self.aThreadSpace) + '\n'
        output += 'aVBAExceptionhandler: ' + hex(self.aVBAExceptionhandler) + '\n'
        output += 'aNativeCode         : ' + hex(self.aNativeCode) + '\n'
        output += 'IdentifierStr_char  : ' + self.IdentifierStr_char + '\n'
        output += 'aExternalTable      : ' + hex(self.aExternalTable) + '\n'
        output += 'lExternalCount      : ' + hex(self.lExternalCount) + '\n\n'
        output += self.objectTable.__str__()
        return output


# ObjectTable structure
class ObjectTable(object):

    def __init__(self, pe, offset):
        self.offset = offset
        self._unpack(pe.mapped)
        self.TObjectTable = []
        for index in xrange(self.iObjectsCount):
            self.TObjectTable.append(TObject(pe, self.aObjectsArray + index * 48 - pe.optionalHeader.ImageBase))

    def _unpack(self, data):
        header_struct = struct.unpack("<LLLLLLLLLLHHHHLLLLLLLLL", data[self.offset:self.offset+84])
        self.lNull1           = header_struct[0]
        self.aExecProj        = header_struct[1]
        self.aProjectInfo2    = header_struct[2]
        self.lConst1          = header_struct[3]
        self.lNull2           = header_struct[4]
        self.aProjectObject   = header_struct[5]
        self.uuidObjectTable  = header_struct[6]
        self.Flag2            = header_struct[7]
        self.Flag3            = header_struct[8]
        self.Flag4            = header_struct[9]
        self.fCompileType     = header_struct[10]
        self.iObjectsCount    = header_struct[11] # Count of objects
        self.iCompiledObjects = header_struct[12]
        self.iObjectsInUse    = header_struct[13]
        self.aObjectsArray    = header_struct[14] # Pointer to objects array
        self.lNull3           = header_struct[15]
        self.lNull4           = header_struct[16]
        self.lNull5           = header_struct[17]
        self.aNTSProjectName  = header_struct[18]
        self.lLcID1           = header_struct[19]
        self.lLcID2           = header_struct[20]
        self.lNull6           = header_struct[21]
        self.lTemplateVersion = header_struct[22]

    def __str__(self):
        output =  'ObjectTable:\n----------\n'
        output += 'lNull1          : ' + hex(self.lNull1) + '\n'
        output += 'aExecProj       : ' + hex(self.aExecProj) + '\n'
        output += 'aProjectInfo2   : ' + hex(self.aProjectInfo2) + '\n'
        output += 'lConst1         : ' + hex(self.lConst1) + '\n'
        output += 'lNull2          : ' + hex(self.lNull2) + '\n'
        output += 'aProjectObject  : ' + hex(self.aProjectObject) + '\n'
        output += 'uuidObjectTable : ' + hex(self.uuidObjectTable) + '\n'
        output += 'Flag2           : ' + hex(self.Flag2) + '\n'
        output += 'Flag3           : ' + hex(self.Flag3) + '\n'
        output += 'Flag4           : ' + hex(self.Flag4) + '\n'
        output += 'fCompileType    : ' + hex(self.fCompileType) + '\n'
        output += 'iObjectsCount   : ' + hex(self.iObjectsCount) + '\n'
        output += 'iCompiledObjects: ' + hex(self.iCompiledObjects) + '\n'
        output += 'iObjectsInUse   : ' + hex(self.iObjectsInUse) + '\n'
        output += 'aObjectsArray   : ' + hex(self.aObjectsArray) + '\n'
        output += 'lNull3          : ' + hex(self.lNull3) + '\n'
        output += 'lNull4          : ' + hex(self.lNull4) + '\n'
        output += 'lNull5          : ' + hex(self.lNull5) + '\n'
        output += 'aNTSProjectName : ' + hex(self.aNTSProjectName) + '\n'
        output += 'lLcID1          : ' + hex(self.lLcID1) + '\n'
        output += 'lLcID2          : ' + hex(self.lLcID2) + '\n'
        output += 'lNull6          : ' + hex(self.lNull6) + '\n'
        output += 'lTemplateVersion: ' + hex(self.lTemplateVersion) + '\n'
        for tobject in self.TObjectTable:
            output += tobject.__str__() + '\n'
        return output


class TObjectInfo(object):

    def __init__(self, pe, offset):
        self.offset = offset
        self._unpack(pe.mapped)

    def _unpack(self, data):
        header_struct = struct.unpack("<HHLLLLLLLHHLHHLLL", data[self.offset:self.offset+56])
        self.wRefCount       = header_struct[0]
        self.wObjectIndex    = header_struct[1]
        self.lpObjectTable   = header_struct[2]
        self.lpIdeData       = header_struct[3]
        self.lpPrivateObject = header_struct[4]
        self.dwReserved      = header_struct[5]
        self.dwNull          = header_struct[6]
        self.lpObject        = header_struct[7]
        self.lpProjectData   = header_struct[8]
        self.wMethodCount    = header_struct[9]
        self.wMethodCount2   = header_struct[10]
        self.lpMethods       = header_struct[11]
        self.wConstants      = header_struct[12]
        self.wMaxConstants   = header_struct[13]
        self.lpIdeData2      = header_struct[14]
        self.lpIdeData3      = header_struct[15]
        self.lpConstants     = header_struct[16]

    def __str__(self):
        output =  'TObjectInfo:\n-----------\n'
        output += 'wRefCount      : ' + hex(self.wRefCount) + '\n'
        output += 'wObjectIndex   : ' + hex(self.wObjectIndex) + '\n'
        output += 'lpObjectTable  : ' + hex(self.lpObjectTable) + '\n'
        output += 'lpIdeData      : ' + hex(self.lpIdeData) + '\n'
        output += 'lpPrivateObject: ' + hex(self.lpPrivateObject) + '\n'
        output += 'dwReserved     : ' + hex(self.dwReserved) + '\n'
        output += 'dwNull         : ' + hex(self.dwNull) + '\n'
        output += 'lpObject       : ' + hex(self.lpObject) + '\n'
        output += 'lpProjectData  : ' + hex(self.lpProjectData) + '\n'
        output += 'wMethodCount   : ' + hex(self.wMethodCount) + '\n'
        output += 'wMethodCount2  : ' + hex(self.wMethodCount2) + '\n'
        output += 'lpMethods      : ' + hex(self.lpMethods) + '\n'
        output += 'wConstants     : ' + hex(self.wConstants) + '\n'
        output += 'wMaxConstants  : ' + hex(self.wMaxConstants) + '\n'
        output += 'lpIdeData2     : ' + hex(self.lpIdeData2) + '\n'
        output += 'lpIdeData3     : ' + hex(self.lpIdeData3) + '\n'
        output += 'lpConstants    : ' + hex(self.lpConstants) + '\n'
        return output


class TObject(object):

    def __init__(self, pe, offset):
        self.offset = offset
        self._unpack(pe)
        self.tObjectInfo = TObjectInfo(pe, self.aObjectInfo - pe.optionalHeader.ImageBase)
        self.procTable = []
        for index in xrange(self.tObjectInfo.wMethodCount):
            address = self.tObjectInfo.lpMethods - pe.optionalHeader.ImageBase + index * 4
            procDscInfo = struct.unpack("<L", pe.mapped[address:address+4])[0]
            if procDscInfo > pe.optionalHeader.ImageBase and procDscInfo < 0x500000:
                # Appended to procTable
                self.procTable.append(ProcDscInfo(pe, procDscInfo - pe.optionalHeader.ImageBase))
            else:
                # Not appended because this ProcDscInfo is outside scope
                pass
        

    def _unpack(self, pe):
        header_struct = struct.unpack("<LLLLLLLLLLLL", pe.mapped[self.offset:self.offset+48])
        self.aObjectInfo      = header_struct[0]  # Pointer to ObjectInfo
        self.lConst1          = header_struct[1]
        self.aPublicBytes     = header_struct[2]  # Pointer to Public Variable Size integers
        self.aStaticBytes     = header_struct[3]  # Pointer to Static Variables Struct
        self.aModulePublic    = header_struct[4]  # Memory Pointer to Public Variables
        self.aModuleStatic    = header_struct[5]  # Pointer to Static Variables
        offset = header_struct[6] - pe.optionalHeader.ImageBase
        end = pe.mapped[offset:].find('\0')
        self.aNTSObjectName   = pe.mapped[offset:offset+end] # Pointer to Object Name
        self.lMethodCount     = header_struct[7]  # Number of methods
        self.aMethodNameTable = header_struct[8]  # Pointer to method names array
        self.oStaticVars      = header_struct[9]  # Offset to Static Vars from aModuleStatic
        self.lObjectType      = header_struct[10] # Flags defining this object behaviour
        self.lNull2           = header_struct[11]

    def __str__(self):
        output =  'TObject:\n--------\n'
        output += 'aObjectInfo     : ' + hex(self.aObjectInfo) + '\n'
        output += 'lConst1         : ' + hex(self.lConst1) + '\n'
        output += 'aPublicBytes    : ' + hex(self.aPublicBytes) + '\n'
        output += 'aStaticBytes    : ' + hex(self.aStaticBytes) + '\n'
        output += 'aModulePublic   : ' + hex(self.aModulePublic) + '\n'
        output += 'aModuleStatic   : ' + hex(self.aModuleStatic) + '\n'
        output += 'aNTSObjectName  : ' + self.aNTSObjectName + '\n'
        output += 'lMethodCount    : ' + hex(self.lMethodCount) + '\n'
        output += 'aMethodNameTable: ' + hex(self.aMethodNameTable) + '\n'
        output += 'oStaticVars     : ' + hex(self.oStaticVars) + '\n'
        output += 'lObjectType     : ' + hex(self.lObjectType) + '\n'
        output += 'lNull2          : ' + hex(self.lNull2) + '\n\n'
        output += self.tObjectInfo.__str__() + '\n'
        for proc in self.procTable:
            output += proc.__str__() + '\n'
        return output


# ProcDscInfo Structure
class ProcDscInfo(object):

    def __init__(self, pe, offset):
        self.offset = offset
        self.ProcAddress = self.offset + pe.optionalHeader.ImageBase
        self._unpack(pe.mapped)
        self.procTable = ProcTable(pe, self.ProcTable - pe.optionalHeader.ImageBase)
        self.pcodes = pe.mapped[self.offset - self.ProcSize:self.offset]

    def _unpack(self, data):
        header_struct = struct.unpack("<LHHH", data[self.offset:self.offset+10])
        self.ProcTable = header_struct[0]
        self.field_4   = header_struct[1]
        self.FrameSize = header_struct[2]
        self.ProcSize  = header_struct[3]

    def __str__(self):
        output =  'ProcDscInfo:\n------------\n'
        output += 'ProcAddress: ' + hex(self.ProcAddress) + '\n'
        output += 'ProcSize : ' + hex(self.ProcSize) + '\n'
        output += self.procTable.__str__()
        #output += 'P-codes:\n'
        #output += "".join("%02x " % ord(b) for b in self.pcodes) + '\n'
        #output += '\n---- End Of P-codes ----\n'
        db = pcodes.PcodeDecoder()
        offset = 0
        while offset < len(self.pcodes):
            pcode = db.get_pcode(self.pcodes, offset)
            if pcode == None:
                break
            (name, size) = pcode
            #output += hex(offset) + "\t" + name + " -- size: " + str(size) + '\n'
            output += hex(offset) + "\t" + name + " -- size: " + str(size) + '\n'
            #for byte in self.pcodes[offset:offset+size]:
            #    output += hex(ord(byte)) + ' '
            #output += '\n'
            offset += size
            
        return output


# ProcTable Structure
class ProcTable(object):

    def __init__(self, pe, offset):
        self.offset = offset
        self._unpack(pe.mapped)

    def _unpack(self, data):
        header_struct = struct.unpack("<52sL", data[self.offset:self.offset+56])
        self.SomeTemp  = header_struct[0]
        self.DataConst = header_struct[1]

    def __str__(self):
        output =  'ProcTable:\n----------\n'
        output += 'DataConst: ' + hex(self.DataConst) + '\n'
        return output
