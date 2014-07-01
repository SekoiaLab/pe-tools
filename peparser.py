'''
Created on 25 avr. 2014

@author: Christophe
'''

import os
import mmap
import struct
import time
import signeddata

IMAGE_DOS_SIGNATURE=0x5A4D
IMAGE_NT_OPTIONAL_HDR32_MAGIC=0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC=0x20b
IMAGE_NT_SIGNATURE=0x00004550

sizeof_IMAGE_FILE_HEADER=20
sizeof_IMAGE_NT_SIGNATURE=4
sizeof_IMAGE_SECTION_HEADER=40

IMAGE_DIRECTORY_ENTRY_EXPORT=0
IMAGE_DIRECTORY_ENTRY_IMPORT=1
IMAGE_DIRECTORY_ENTRY_RESOURCE=2
IMAGE_DIRECTORY_ENTRY_EXCEPTION=3
IMAGE_DIRECTORY_ENTRY_SECURITY=4
IMAGE_DIRECTORY_ENTRY_BASERELOC=5
IMAGE_DIRECTORY_ENTRY_DEBUG=6
IMAGE_DIRECTORY_ENTRY_COPYRIGHT=7
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE=7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR=8
IMAGE_DIRECTORY_ENTRY_TLS=9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG=10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT=11
IMAGE_DIRECTORY_ENTRY_IAT=12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT=13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR=14
IMAGE_DIRECTORY_ENTRY_RESERVED=15
    
OPTIONAL_HEADER_MAGIC_32=0x10b
OPTIONAL_HEADER_MAGIC_64=0x20b

DataDirectoryType = [
    'IMAGE_DIRECTORY_ENTRY_EXPORT',          # Export Directory
    'IMAGE_DIRECTORY_ENTRY_IMPORT',          # Import Directory
    'IMAGE_DIRECTORY_ENTRY_RESOURCE',        # Resource Directory
    'IMAGE_DIRECTORY_ENTRY_EXCEPTION',       # Exception Directory
    'IMAGE_DIRECTORY_ENTRY_SECURITY',        # Security Directory
    'IMAGE_DIRECTORY_ENTRY_BASERELOC',       # Base Relocation Table
    'IMAGE_DIRECTORY_ENTRY_DEBUG',           # Debug Directory
    'IMAGE_DIRECTORY_ENTRY_COPYRIGHT',       # (X86 usage)
    #'IMAGE_DIRECTORY_ENTRY_ARCHITECTURE',    # Architecture Specific Data
    'IMAGE_DIRECTORY_ENTRY_GLOBALPTR',       # RVA of GP
    'IMAGE_DIRECTORY_ENTRY_TLS',             # TLS Directory
    'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',     # Load Configuration Directory
    'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',    # Bound Import Directory in headers
    'IMAGE_DIRECTORY_ENTRY_IAT',             # Import Address Table
    'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',    # Delay Load Import Descriptors
    'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',  # COM Runtime descriptor
    'IMAGE_DIRECTORY_ENTRY_RESERVED'         # reserved descriptor
]


class DosHeader(object):

    def __init__(self, data):
        self._unpack(data)
        
    def _unpack(self, data):
        header_struct = struct.unpack("<HHHHHHHHHHHHHH8sHH20sL",data[:64])
        self.e_magic    = header_struct[0]
        self.e_cblp     = header_struct[1]
        self.e_cp       = header_struct[2]
        self.e_crlc     = header_struct[3]
        self.e_cparhdr  = header_struct[4]
        self.e_minalloc = header_struct[5]
        self.e_maxalloc = header_struct[6]
        self.e_ss       = header_struct[7]
        self.e_sp       = header_struct[8]
        self.e_csum     = header_struct[9]
        self.e_ip       = header_struct[10]
        self.e_cs       = header_struct[11]
        self.e_lfarlc   = header_struct[12]
        self.e_ovno     = header_struct[13]
        #self.e_res      = header_struct[14]
        self.e_oemid    = header_struct[15]
        self.e_oeminfo  = header_struct[16]
        #self.e_res2     = header_struct[17]
        self.e_lfanew   = header_struct[18]

    def __str__(self):
        output = 'DOS header:\n----------\n'
        output += 'e_magic   : ' + str(hex(self.e_magic)) + '\n'
        output += 'e_cblp    : ' + str(hex(self.e_cblp)) + '\n'
        output += 'e_cp      : ' + str(hex(self.e_cp)) + '\n'
        output += 'e_crlc    : ' + str(hex(self.e_crlc)) + '\n'
        output += 'e_cparhdr : ' + str(hex(self.e_cparhdr)) + '\n'
        output += 'e_minalloc: ' + str(hex(self.e_minalloc)) + '\n'
        output += 'e_maxalloc: ' + str(hex(self.e_maxalloc)) + '\n'
        output += 'e_ss      : ' + str(hex(self.e_ss)) + '\n'
        output += 'e_sp      : ' + str(hex(self.e_sp)) + '\n'
        output += 'e_csum    : ' + str(hex(self.e_csum)) + '\n'
        output += 'e_ip      : ' + str(hex(self.e_ip)) + '\n'
        output += 'e_cs      : ' + str(hex(self.e_cs)) + '\n'
        output += 'e_lfarlc  : ' + str(hex(self.e_lfarlc)) + '\n'
        output += 'e_ovno    : ' + str(hex(self.e_ovno)) + '\n'
        output += 'e_oemid   : ' + str(hex(self.e_oemid)) + '\n'
        output += 'e_oeminfo : ' + str(hex(self.e_oeminfo)) + '\n'
        output += 'e_lfanew  : ' + str(hex(self.e_lfanew)) + '\n\n'
        return output


class FileHeader(object):

    def __init__(self, data, offset):
        self.offset = offset
        self._unpack(data)
        
    def _unpack(self, data):
        header_struct = struct.unpack("<HHLLLHH", data[self.offset:self.offset+sizeof_IMAGE_FILE_HEADER])
        self.Machine              = header_struct[0]
        self.NumberOfSections     = header_struct[1]
        self.TimeDateStamp        = header_struct[2]
        self.PointerToSymbolTable = header_struct[3]
        self.NumberOfSymbols      = header_struct[4]
        self.SizeOfOptionalHeader = header_struct[5]
        self.Characteristics      = header_struct[6]

    def __str__(self):
        output = 'File header:\n-----------\n'
        output += 'Machine             : ' + hex(self.Machine) + '\n'
        output += 'NumberOfSections    : ' + str(self.NumberOfSections) + '\n'
        output += 'TimeDateStamp       : ' + time.ctime(self.TimeDateStamp) + '\n'
        output += 'PointerToSymbolTable: ' + hex(self.PointerToSymbolTable) + '\n'
        output += 'NumberOfSymbols     : ' + str(self.NumberOfSymbols) + '\n'
        output += 'SizeOfOptionalHeader: ' + str(self.SizeOfOptionalHeader) + '\n'
        output += 'Characteristics     : ' + hex(self.Characteristics) + '\n\n'
        return output


class Section(object):

    def __init__(self, data, offset):
        self.offset = offset
        self._unpack(data)
        
    def _unpack(self, data):
        header_struct = struct.unpack("<8sLLLLLLHHL", data[self.offset:self.offset+40])
        self.Name                 = header_struct[0]
        self.VirtualSize          = header_struct[1]
        self.VirtualAddress       = header_struct[2]
        self.SizeOfRawData        = header_struct[3]
        self.PointerToRawData     = header_struct[4]
        self.PointerToRelocations = header_struct[5]
        self.PointerToLinenumbers = header_struct[6]
        self.NumberOfRelocations  = header_struct[7]
        self.NumberOfLinenumbers  = header_struct[8]
        self.Characteristics      = header_struct[9]

    def __str__(self):
        output = 'Section header:\n--------------\n'
        output += 'Name:                 ' + self.Name + '\n'
        output += 'VirtualSize:          ' + hex(self.VirtualSize) + '\n'
        output += 'VirtualAddress:       ' + hex(self.VirtualAddress) + '\n'
        output += 'SizeOfRawData:        ' + hex(self.SizeOfRawData) + '\n'
        output += 'PointerToRawData:     ' + hex(self.PointerToRawData) + '\n'
        output += 'PointerToRelocations: ' + hex(self.PointerToRelocations) + '\n'
        output += 'PointerToLinenumbers: ' + hex(self.PointerToLinenumbers) + '\n'
        output += 'NumberOfRelocations:  ' + hex(self.NumberOfRelocations) + '\n'
        output += 'NumberOfLinenumbers:  ' + hex(self.NumberOfLinenumbers) + '\n'
        output += 'Characteristics:      ' + hex(self.Characteristics) + '\n\n'
        return output


class Signature(object):

    def __init__(self, data, offset, size):
        print 'Signature -- Address=', hex(offset), 'Size=', hex(size)
        self.offset = offset
        self.size   = size
        self._unpack(data)
        
    def _unpack(self, data):
        header_struct = struct.unpack("<LHH", data[self.offset:self.offset+8])
        self.Length          = header_struct[0]
        self.Revision        = header_struct[1]
        self.CertificateType = header_struct[2]
        #self.bCertificate    = bytearray(data[self.offset+8:self.offset+8+self.Length])
        self.bCertificate    = data[self.offset+8:self.offset+8+self.Length]
        #print 'Signature -- Length=', self.Length
        #print 'bCertificate Length=', len(self.bCertificate)

    def saveDerToFile(self, filename):
        # save signature to a file (skip 19 bytes to remove SEQUENCE+OBJECTID+[0] structures)
        with open(filename, "wb") as f:
            f.write(self.bCertificate[19:])
            
    def saveCertificatesNamesToCsvFile(self, filename):
        sd = signeddata.SignedData(self.bCertificate[19:])
        names = sd.getNamesFromCertificate('issuer')
        names += sd.getNamesFromCertificate('subject')
        with open(filename, "w") as f:
            f.write(names)

    def __str__(self):
        output = 'Security signature:\n--------------\n'
        output += 'Length:         ' + hex(self.Length) + '\n'
        output += 'Revision:       ' + hex(self.Revision) + '\n'
        output += 'CertificateType:' + hex(self.CertificateType)
        return output


class OptionalHeader(object):

    def __init__(self, data, offset):
        self.DataDirectories = []
        self.offset = offset
        self._unpack(data)
        
    def _unpack(self, data):
        header_struct = struct.unpack("<HBBLLLLL", data[self.offset:self.offset+24])
        self.offset += struct.calcsize("<HBBLLLLL")
        self.Magic                   = header_struct[0]
        self.MajorLinkerVersion      = header_struct[1]
        self.MinorLinkerVersion      = header_struct[2]
        self.SizeOfCode              = header_struct[3]
        self.SizeOfInitializedData   = header_struct[4]
        self.SizeOfUninitializedData = header_struct[5]
        self.AddressOfEntryPoint     = header_struct[6]
        self.BaseOfCode              = header_struct[7]

        if self.Magic == 0x10b: #32bits
            header_struct = struct.unpack("<LL", data[self.offset:self.offset+8])
            self.offset += struct.calcsize("<LL")
            self.BaseOfData          = header_struct[0]
            self.ImageBase           = header_struct[1]
        elif self.Magic == 0x20b: #64bits
            header_struct = struct.unpack("<Q", data[self.offset:self.offset+8])
            self.offset += struct.calcsize("<Q")
            self.ImageBase = header_struct[0]
        else:
            self.ImageBase           = 0
            self.Errors += 'OptionalHeader.__init__: self.Magic has unknown value ('+ hex(self.Magic) + ')\n' 

        header_struct = struct.unpack("<LLHHHHHHLLLLHH", data[self.offset:self.offset+40])
        self.offset += struct.calcsize("<LLHHHHHHLLLLHH")
        self.SectionAlignment            = header_struct[0]
        self.FileAlignment               = header_struct[1]
        self.MajorOperatingSystemVersion = header_struct[2]
        self.MinorOperatingSystemVersion = header_struct[3]
        self.MajorImageVersion           = header_struct[4]
        self.MinorImageVersion           = header_struct[5]
        self.MajorSubsystemVersion       = header_struct[6]
        self.MinorSubsystemVersion       = header_struct[7]
        self.Win32VersionValue           = header_struct[8]
        self.SizeOfImage                 = header_struct[9]
        self.SizeOfHeaders               = header_struct[10]
        self.CheckSum                    = header_struct[11]
        self.Subsystem                   = header_struct[12]
        self.DllCharacteristics          = header_struct[13]
        
        if self.Magic   == 0x10b: #32bits
            header_struct = struct.unpack("<LLLL", data[self.offset:self.offset+16])
            self.offset += struct.calcsize("<LLLL")
        elif self.Magic == 0x20b: #64bits
            header_struct = struct.unpack("<QQQQ", data[self.offset:self.offset+32])
            self.offset += struct.calcsize("<QQQQ")
        else:
            self.Errors += 'OptionalHeader.__init__: self.Magic has unknown value ('+ hex(self.Magic) + ')\n' 

        self.SizeOfStackReserve = header_struct[0]
        self.SizeOfStackCommit  = header_struct[1]
        self.SizeOfHeapReserve  = header_struct[2]
        self.SizeOfHeapCommit   = header_struct[3]

        header_struct = struct.unpack("<LL", data[self.offset:self.offset+8])
        self.offset += struct.calcsize("<LL")
        self.LoaderFlags         = header_struct[0]
        self.NumberOfRvaAndSizes = header_struct[1]

        # parse the array of data directories
        for index in xrange(self.NumberOfRvaAndSizes):
            VirtualAddress, Size = struct.unpack("<LL", data[self.offset+8*index:self.offset+8*(index+1)])
            self.DataDirectories.append((index, VirtualAddress, Size))

    def __str__(self):
        output =  'Optional header:\n---------------\n'
        output += 'Magic                       : ' + hex(self.Magic) + '\n'
        output += 'MajorLinkerVersion          : ' + hex(self.MajorLinkerVersion) + '\n'
        output += 'MinorLinkerVersion          : ' + hex(self.MinorLinkerVersion) + '\n'
        output += 'SizeOfCode                  : ' + hex(self.SizeOfCode) + '\n'
        output += 'SizeOfInitializedData       : ' + hex(self.SizeOfInitializedData) + '\n'
        output += 'SizeOfUninitializedData     : ' + hex(self.SizeOfUninitializedData) + '\n'
        output += 'AddressOfEntryPoint         : ' + hex(self.AddressOfEntryPoint) + '\n'
        output += 'BaseOfCode                  : ' + hex(self.BaseOfCode) + '\n'
        if self.Magic == 0x10b: #32bits
            output += 'BaseOfData  : ' + hex(self.BaseOfData) + '\n'
        output += 'ImageBase                   : ' + hex(self.ImageBase) + '\n'
        output += 'SectionAlignment            : ' + hex(self.SectionAlignment) + '\n'
        output += 'FileAlignment               : ' + hex(self.FileAlignment) + '\n'
        output += 'MajorOperatingSystemVersion : ' + hex(self.MajorOperatingSystemVersion) + '\n'
        output += 'MinorOperatingSystemVersion : ' + hex(self.MinorOperatingSystemVersion) + '\n'
        output += 'MajorImageVersion           : ' + hex(self.MajorImageVersion) + '\n'
        output += 'MinorImageVersion           : ' + hex(self.MinorImageVersion) + '\n'
        output += 'MajorSubsystemVersion       : ' + hex(self.MajorSubsystemVersion) + '\n'
        output += 'MinorSubsystemVersion       : ' + hex(self.MinorSubsystemVersion) + '\n'
        output += 'Win32VersionValue           : ' + hex(self.Win32VersionValue) + '\n'
        output += 'SizeOfImage                 : ' + hex(self.SizeOfImage) + '\n'
        output += 'SizeOfHeaders               : ' + hex(self.SizeOfHeaders) + '\n'
        output += 'CheckSum                    : ' + hex(self.CheckSum) + '\n'
        output += 'Subsystem                   : ' + hex(self.Subsystem) + '\n'
        output += 'DllCharacteristics          : ' + hex(self.DllCharacteristics) + '\n'
        output += 'SizeOfStackReserve          : ' + hex(self.SizeOfStackReserve) + '\n'
        output += 'SizeOfStackCommit           : ' + hex(self.SizeOfStackCommit) + '\n'
        output += 'SizeOfHeapReserve           : ' + hex(self.SizeOfHeapReserve) + '\n'
        output += 'SizeOfHeapCommit            : ' + hex(self.SizeOfHeapCommit) + '\n'
        output += 'LoaderFlags                 : ' + hex(self.LoaderFlags) + '\n'
        output += 'NumberOfRvaAndSizes         : ' + hex(self.NumberOfRvaAndSizes) + '\n\n'
        for descriptor in self.DataDirectories:
            output +=  DataDirectoryType[int(descriptor[0])] + ':\n--------------------------\n'
            output += 'VirtualAddress: ' + hex(descriptor[1]) + '\n'
            output += 'Size:           ' + hex(descriptor[2]) + '\n'
        output += '\n'
        return output


class ImportDescriptor(object):

    def __init__(self, Name, thunk, RVA, func_name, ordinal, hint):
        self.Name = Name
        self.OriginalThunk = thunk
        self.Thunk = RVA
        self.FuncName = func_name
        self.Ordinal = ordinal
        self.Hint = hint

    def __str__(self):
        output  = 'Name         : ' + self.Name + '\n'
        output += 'OriginalThunk: ' + hex(self.OriginalThunk) + '\n'
        output += 'Thunk        : ' + hex(self.Thunk) + '\n'
        output += 'FuncName     : ' + self.FuncName + '\n'
        output += 'Ordinal      : ' + hex(self.Ordinal) + '\n'
        output += 'Hint         : ' + hex(self.Hint)
        output += '\n'
        return output


class PeParser(object):

    def __init__(self, filename):
        # clear attributes
        self.Sections = []
        self.Imports = []
        self.Errors = ''
        self.signature = None
        # start parsing
        self.open(filename)
        if self.mapped == None:
            print 'Unable to open ', filename
            return
        # get DOS header
        self.dosHeader = DosHeader(self.mapped)
        if self.dosHeader.e_magic != IMAGE_DOS_SIGNATURE:
            print filename, ' is not a PE file.'
            return
        # get NT header
        self.nt_header = self._get_nt_header(self.dosHeader.e_lfanew)

    def open(self, filename):
        try:
            f=open(filename, "rb")
            self.filename = filename
            self.filesize = os.path.getsize(filename)
            try:
                self.mapped = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            except:
                self.mapped = None
            finally:
                f.close()
        except IOError:
            pass

    def _get_nt_header(self, offset):
        # get PE Header signature
        self.PeHeaderSignature = struct.unpack("<L", self.mapped[offset:offset+sizeof_IMAGE_NT_SIGNATURE])[0]
        # get file header
        self.fileHeader = FileHeader(self.mapped, offset + sizeof_IMAGE_NT_SIGNATURE)
        # get sections
        if self.fileHeader.NumberOfSections > 0:
            soffset = offset + sizeof_IMAGE_NT_SIGNATURE + sizeof_IMAGE_FILE_HEADER + self.fileHeader.SizeOfOptionalHeader
            for index in xrange(self.fileHeader.NumberOfSections):
                self.Sections.append(Section(self.mapped, soffset+index*sizeof_IMAGE_SECTION_HEADER))
        # get optional header
        self.optionalHeader = OptionalHeader(self.mapped, offset + sizeof_IMAGE_NT_SIGNATURE + sizeof_IMAGE_FILE_HEADER)
        # get import table
        if len(self.optionalHeader.DataDirectories) > IMAGE_DIRECTORY_ENTRY_IMPORT:
            (index, VirtualAddress, Size) = self.optionalHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT]
            self._get_import_table(self.RVAtoOffset(VirtualAddress), Size)
            
        if len(self.optionalHeader.DataDirectories) > IMAGE_DIRECTORY_ENTRY_SECURITY:
            (index, VirtualAddress, Size) = self.optionalHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY]
            self.signature = Signature(self.mapped, VirtualAddress, Size)

    def __str__nt_header(self):
        output = 'NT header:\n---------\n'
        output += 'Signature: ' + hex(self.PeHeaderSignature) + '\n\n'
        output += self.fileHeader.__str__()
        output += self.optionalHeader.__str__()
        for section in self.Sections:
            output += section.__str__()
        return output

    def _get_import_table(self, offset, size):
        if size % 20 != 0:
            return
        for index in xrange((size / 20) - 1):
            self._get_import_descriptors(offset+20*index)

    def _get_import_descriptors(self, offset):
        #print 'filesize=', str(self.filesize)
        #print 'offset=', hex(offset)
        header_struct = struct.unpack("<LLLLL", self.mapped[offset:offset+20])
        OriginalFirstThunk = header_struct[0]
        TimeDateStamp      = header_struct[1]
        ForwarderChain     = header_struct[2]
        #print 'OriginalFirstThunk=', hex(OriginalFirstThunk)
        #print 'TimeDateStamp=', hex(TimeDateStamp)
        #print 'ForwarderChain=', hex(ForwarderChain)
        end  = self.mapped[self.RVAtoOffset(header_struct[3]):].find('\0')
        Name = self.mapped[self.RVAtoOffset(header_struct[3]):self.RVAtoOffset(header_struct[3])+end]
        #print 'Name=', Name
        FirstThunk = header_struct[4]
        thunk = self.RVAtoOffset(OriginalFirstThunk)
        #print 'result=', hex(thunk)
        if thunk == -1:
            self.Errors += 'get_import_descriptors: Invalid entry\n'
            self.Errors += '  OriginalFirstThunk= ' + hex(OriginalFirstThunk) + '\n'
            self.Errors += '  TimeDateStamp     = ' + hex(TimeDateStamp) + '\n'
            self.Errors += '  ForwarderChain    = ' + hex(ForwarderChain) + '\n'
            self.Errors += '  Name              = ' + Name + '\n'
            self.Errors += '  FirstThunk        = ' + hex(FirstThunk) + '\n'
            return
        RVA   = FirstThunk
        #print 'Thunk=', hex(thunk)
        if self.optionalHeader.Magic   == 0x10b: #32bits
            #print 'result=', hex(self.RVAtoOffset(thunk))
            AddressOfData = struct.unpack("<L", self.mapped[thunk:thunk+4])[0]
        elif self.PeOptionalHeaderMagic == 0x20b: #64bits
            AddressOfData = struct.unpack("<Q", self.mapped[thunk:thunk+8])[0]
        else:
            AddressOfData = 0
            self.Errors += 'get_import_descriptors: self.PeOptionalHeaderMagic has unknown value ('+ hex(self.PeOptionalHeaderMagic) + ')\n' 
        while AddressOfData <> 0:
            func_name = ''
            ordinal = 0
            hint = 0
            # check for validity of entries
            if self.optionalHeader.Magic   == 0x10b: #32bits
                mask = 1 << 31
            elif self.optionalHeader.Magic == 0x20b: #64bits
                mask = 1 << 63
            if (AddressOfData >= mask):
                # ordinal type
                #print 'Import by ordinal'
                ordinal= AddressOfData & (mask - 1)
            else:
                hint = struct.unpack("<H", self.mapped[self.RVAtoOffset(AddressOfData):self.RVAtoOffset(AddressOfData)+2])[0]
                end = self.mapped[self.RVAtoOffset(AddressOfData)+2:].find('\0')
                func_name= self.mapped[self.RVAtoOffset(AddressOfData)+2:self.RVAtoOffset(AddressOfData)+2+end]
            self.Imports.append(ImportDescriptor(Name, thunk, RVA, func_name, ordinal, hint))
            if self.optionalHeader.Magic   == 0x10b: #32bits
                thunk += 4
                RVA += 4 
                AddressOfData = struct.unpack("<L", self.mapped[thunk:thunk+4])[0]
            elif self.optionalHeader.Magic == 0x20b: #64bits
                thunk += 8
                RVA += 8 
                AddressOfData = struct.unpack("<Q", self.mapped[thunk:thunk+8])[0]
            #print 'Extracted AddressOfData: ', hex(AddressOfData)

    def __str__import_descriptors(self):
        output = ''
        output += 'DLL Name            |thunk   |RVA     |func_name                    |ordinal  |hint\n'
        for descr in self.Imports:
            output += '{:<20}'.format(descr.Name) + '|'
            output += '{:>8}'.format(hex(descr.OriginalThunk)) + '|'
            output += '{:>8}'.format(hex(descr.Thunk)) + '|'
            output += '{:<29}'.format(descr.FuncName) + '|'
            output += '{:>9}'.format(hex(descr.Ordinal)) + '|'
            output += '{:>10}'.format(hex(descr.Hint))
            output += '\n'
        return output

    def get_overlay(self):
        # get the last section offset and length
        s = self.Sections[-1]
        if (self.filesize > s.PointerToRawData + s.SizeOfRawData):
            return self.mapped[s.PointerToRawData + s.SizeOfRawData:]

    def dump_info(self):
        print self.dosHeader
        print self.__str__nt_header()
        print self.__str__import_descriptors()

    def dump_errors(self):
        print 'Errors:\n-------'
        print self.Errors
        
    def RVAtoOffset(self, rva):
        for s in self.Sections:
            if rva >= s.VirtualAddress and rva < s.VirtualAddress + s.SizeOfRawData:
                return rva - s.VirtualAddress + s.PointerToRawData
        if rva < self.Sections[0].VirtualAddress:
            return rva # rva is in header

        return -1

