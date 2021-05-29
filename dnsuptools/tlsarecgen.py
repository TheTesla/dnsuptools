#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

from OpenSSL import crypto
import hashlib

def tlsaFromCertFile(certFilename, certConstr = 3, keyOnly = 0, hashType = 1):
    with open(certFilename) as f:
        certCont = f.read()
    if 2 == int(certConstr) or 0 == int(certConstr):
        certCont = certCont.split('-----END CERTIFICATE-----')[1]
        certCont += '-----END CERTIFICATE-----'
    certObj = crypto.load_certificate(crypto.FILETYPE_PEM, certCont)
    if 0 == int(keyOnly):
        ASN1 = crypto.dump_certificate(crypto.FILETYPE_ASN1, certObj)
    else:
        pubKeyObj = certObj.get_pubkey()
        ASN1 = crypto.dump_publickey(crypto.FILETYPE_ASN1, pubKeyObj)
    if 1 == int(hashType):
        output = hashlib.sha256(ASN1).hexdigest()
    elif 2 == int(hashType):
        output = hashlib.sha512(ASN1).hexdigest()
    return output.encode()

def tlsaRecordsFromCertFile(certFilenames, tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]):
    tlsaList = []
    if type(certFilenames) is list:
        for e in certFilenames:
            tlsaList.extend(tlsaRecordsFromCertFile(e, tlsaTypes))
        return tlsaList
    tlsaDictList = [{'usage': tlsaType[0], 'selector': tlsaType[1], 'matchingtype': tlsaType[2], 'tlsa': tlsaFromCertFile(certFilenames, tlsaType[0], tlsaType[1], tlsaType[2])} for tlsaType in tlsaTypes]
    return tlsaDictList

def tlsaFromFile(tlsaDict):
    if type(tlsaDict) is list:
        rv = [tlsaFromFile(e) for e in tlsaDict]
        tlsaDict[:] = rv
        return rv
    if 'filename' not in tlsaDict:
        return tlsaDict
    tlsaDict['tlsa'] = tlsaFromCertFile(tlsaDict['filename'], tlsaDict['usage'], tlsaDict['selector'], tlsaDict['matchingtype'])
    tlsaDict['tlsa'] = tlsaDict['tlsa'].replace(b'\n', b'')
    return tlsaDict
