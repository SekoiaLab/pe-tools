'''
Created on 15 mai 2014

@author: Christophe
'''

import csv
import struct

class PcodeDecoder(object):
    '''
    This class is used to decode Visual Basic 5/6 functions P-CODE compiled.
    Usage:
    >>> import pcodes
    >>> decoder = pcodes.PcodeDecoder()
    >>> pcode = decoder.get_pcode([0x49])
    >>> if pcode != None:
    >>>   print "pcode name: %s - size=%d" % (pcode[0], pcode[1])
    pcode name: PopAdLd4 - size=1
    >>>
    '''

    def __init__(self):
        '''
        Creates the P-CODES database from CSV file.
        '''
        with open('vb_opcodes.csv', 'rb') as csvfile:
            self.db = dict()
            reader = csv.reader(csvfile, delimiter='@', quotechar='"')
            for row in reader:
                #print ', '.join(row)
                if row[2] != 'DOC':
                    self.db[int(row[0], 16)] = (row[2], int(row[1], 16))
                else:
                    # size value is in fact a reference to another p-code
                    self.db[int(row[0], 16)] = self.db[int(row[1], 16)]
    
    def get_pcode(self, data, offset):
        '''
        Returns a tuple with the name and the size of the first P-CODE in data at offset.
        '''
        remain = len(data) - offset
        if remain < 1:
            return None
        length = 1
        # get p-code from data at offset
        index = struct.unpack(">B", data[offset:offset+1])[0]
        if index > 0xfa:
            if remain < 2:
                return None
            # 2 byte p-code
            length = 2
            index = struct.unpack(">H", data[offset:offset+2])[0]
        if index not in self.db:
            #print 'Unknown P-CODE {} !!!!!!!!!!!!!!!!!!!'.format(hex(index))
            return None
        name = self.db[index][0]
        size = self.db[index][1]
        if size == -1:
            size = length + 2 + struct.unpack("<H", data[offset+length:offset+length+2])[0]
        #print 'get_pcode: ' + hex(index) + ' -- ' + name + ' -- ' + str(size)
        if size + offset > len(data):
            return None
        return (name, size + length - 1) 
        