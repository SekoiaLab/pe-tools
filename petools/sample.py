'''
Created on 22 avr. 2014

@author: Christophe
'''

#!/usr/bin/python

import sys
import peparser
import vbparser
import pcodes


###############################################################################

###############################################################################

def main():
    if len(sys.argv) != 2:
        print('Usage:')
        print('   pe_parser <filename>')
        return
    else:
        print("File scan:\n")
        filename = sys.argv[1]
        print("{} - ".format(filename))
        pe = peparser.PeParser(filename)
        print 'AddressOfEntryPoint: ', hex(pe.optionalHeader.AddressOfEntryPoint + pe.optionalHeader.ImageBase)
        pe.dump_info()
        for section in pe.Sections:
            print section
        for descr in pe.Imports:
            print descr
        vb_header_addr = vbparser.getVbHeaderAddress(pe)
        if vb_header_addr != None:
            print 'vb_header_addr=', hex(vb_header_addr)
            # then decode the VB
            vbHeader = vbparser.VbParser(pe, vb_header_addr)
            print vbHeader
        #print 'Overlay: ', pe.get_overlay()
        pe.dump_errors()
        print("Done\n")
        return

if __name__ == '__main__':
    db = pcodes.PcodeDecoder()
    main()
