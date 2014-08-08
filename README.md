What?
-----

It is a set of python scripts to parse PE and VB5/6 headers in a Windows
executable file. The peparser module analyses PE headers. The vbparser module
analyses VB headers and the pcodes module allows disassembly of p-code functions.
The PE signature can be saved to a file in DER format (pyasn1 needed).

Why?
----

pefile module does not accept invalid PE headers. One of the malware we had to
analyse has got an invalid IMPORT descriptor and it makes pefile report the file
as invalid.

Limitations:
------------

peparser module is, at the moment, limited to DOS, File, Optional ans Section
headers. And from the Optional header it lists the data directories and parse
only the IMPORT one (even if an entry is invalid we continue parsing).
At the moment, the pcodes module cannot show arguments of the p-code.

TODO:
-----
- Add parsing of more data directories in peparser module,
- Add methods in vbparser module to get Visual Basic structures instead of just
  printing them.
- Add p-code arguments display in pcodes module.

Requirements:
-------------
- pyasn1
- pyasn1-modules
- distorm3

Usage:
------
```
>>> import peparser
>>> pe = peparser.PeParser('test.exe')
>>> print 'Address Of Entry Point: ', hex(pe.optionalHeader.AddressOfEntryPoint + pe.optionalHeader.ImageBase)
>>> pe.dump_info()
...
>>> import vbparser
>>> vb_header_addr = vbparser.getVbHeaderAddress(pe)
>>> if vb_header_addr != None:
>>>   vbHeader = vbparser.VbParser(pe, vb_header_addr)
>>>   print vbHeader
...
>>> import pcodes
>>> db = pcodes.PcodeDecoder()
>>> data = '\xfd\x16\x10\x00\x5c\xff\xfd\x16\x14\x00\x4c\xff\xfb\x17\x3c\xff\xfc\xf6\x6c\xff\xfd\x95\x10\x00'
>>> offset = 0
>>> while offset < len(data):
>>>   name, size = db.get_pcode(data, offset)
>>>   print hex(offset), "\t", name, " -- size: ", size
>>>   for byte in data[offset:offset+size]:
>>>     print hex(ord(byte)),
>>>   print '\n'
>>>   offset += size
...
>>> import peparser
>>> pe = peparser.PeParser('file.exe')
>>> if pe.signature is not None:
>>>   pe.signature.saveDerToFile('signeddata.der')
>>>   pe.signature.saveCertificatesNamesToCsvFile('issuer_subject.csv')
```
