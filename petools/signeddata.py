'''
Created on Jun 30, 2014

@author: christophe
'''
from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc2315

class SignedData(object):

    def __init__(self, data):
        self.version = None
        self.digestAlgorithms = None
        self.contentInfo = None
        self.certificates = None
        self.signerInfos= None
        self.createDb()
        # decode DER data as SignedData structure
        self.signeddata, self.rest = decode(data, asn1Spec=rfc2315.SignedData())

    def __str__(self):
        return self.signeddata.prettyPrint()
        
    def version(self):
        return self.signeddata['version']
        
    def digestAlgorithms(self):
        return self.signeddata['digestAlgorithms'].prettyPrint()
        #=======================================================================
        # for da in self.signeddata['digestAlgorithms']:
        #     print da['algorithm']
        #     for p in da['parameters']:
        #         print hexlify(p),
        #     print ''
        #=======================================================================

    def contentInfo(self):
        print self.signeddata['contentInfo'].prettyPrint()
        #=======================================================================
        # print self.signeddata['contentInfo']['contentType']
        # for c in self.signeddata['contentInfo']['content']:
        #     print hexlify(c),
        # print ''
        #=======================================================================
        
    def certificates(self):
        print self.signeddata['certificates'].prettyPrint()
        #=======================================================================
        # for c in self.signeddata['certificates']:
        #     cer = c['certificate']['tbsCertificate'] # just get the core part of the certificate
        # 
        #     print cer['version']
        #     print cer['serialNumber']
        #     print cer['signature'].prettyPrint()
        #     print cer['issuer'].prettyPrint()
        #     print cer['validity'].prettyPrint()        
        #     print cer['subject'].prettyPrint()
        #     print cer['subjectPublicKeyInfo'].prettyPrint()
        #     print cer['extensions'].prettyPrint()
        # 
        #     subject = cer['subject']
        #     rdnsequence = subject[0] # the subject is only composed by one component
        #     for rdn in rdnsequence:
        #         oid, value = rdn[0]  # rdn only has 1 component: (object id, value) tuple
        #         print oid, ':', str(value[2:])
        #=======================================================================
        
    def signerInfos(self):
        print self.signeddata['signerInfos'].prettyPrint()
        
    def createDb(self):
        self.db = dict()
        self.db["2.5.4.3"]  = ("commonName", "CN")
        #self.db["2.5.4.6"]  = ("countryName",  "C")
        #self.db["2.5.4.7"]  = ("localityName", "")
        #self.db["2.5.4.8"]  = ("stateOrProvinceName", "")
        self.db["2.5.4.10"] = ("organizationName", "O")
        self.db["2.5.4.11"] = ("organizationalUnitName", "OU")

    def getNamesFromCertificate(self, issuerOrSubject):
        names = ''
        for c in self.signeddata['certificates']:
            cer = c['certificate']['tbsCertificate'] # just get the core part of the certificate
            role = cer[issuerOrSubject]
            rdnsequence = role[0] # the role (subject or issuer) is only composed by one component
            names += 'role=' + issuerOrSubject  + ';'
            for rdn in rdnsequence:
                oid, value = rdn[0]  # rdn only has 1 component: (object id, value) tuple
                if oid.prettyPrint() in self.db:
                    names += self.db[oid.prettyPrint()][1] + '=' + str(value[2:]) + ';'
            names += '\n'
        return names[:-1]


if __name__ == '__main__':
    derData = file('signature_tr.der', 'rb').read()
    sd = SignedData(derData)
    names = sd.getNamesFromCertificate('issuer')
    names += sd.getNamesFromCertificate('subject')
    with open('signature.csv', "w") as f:
        f.write(names)
