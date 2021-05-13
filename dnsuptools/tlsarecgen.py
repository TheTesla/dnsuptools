#!/usr/bin/env python
# -*- encoding: UTF8 -*-

#from subprocess import check_output, Popen, PIPE
from simpleloggerplus import simpleloggerplus as log
from OpenSSL import crypto
import hashlib

#def tlsaFromCertFile(certFilename, certConstr = 3, keyOnly = 0, hashType = 1):
#    log.debug(certFilename)
#    certCont = check_output(('cat', str(certFilename)))
#    if 2 == int(certConstr) or 0 == int(certConstr):
#        certCont = certCont.split(b'-----END CERTIFICATE-----')[1]
#        certCont += b'-----END CERTIFICATE-----'
#    ps = Popen(('echo', '-e', certCont), stdout=PIPE)
#    if 0 == int(keyOnly):
#        ps = Popen(('openssl', 'x509', '-outform', 'DER'), stdout=PIPE, stdin=ps.stdout)
#    else:
#        ps = Popen(('openssl', 'x509', '-pubkey', '-noout'), stdout=PIPE, stdin=ps.stdout)
#        ps = Popen(('openssl', 'pkey', '-pubin', '-outform', 'DER'), stdin=ps.stdout, stdout=PIPE)
#    if 1 == int(hashType):
#        output = check_output(('openssl', 'sha256'), stdin=ps.stdout)
#    elif 2 == int(hashType):
#        output = check_output(('openssl', 'sha512'), stdin=ps.stdout)
#    log.debug(output)
#    return output.split(b' ')[1]

def tlsaFromCertFile(certFilename, certConstr = 3, keyOnly = 0, hashType = 1):
    #certCont = sp.check_output(('cat', str(certFilename)))
    with open(certFilename) as f:
        certCont = f.read()
    if 2 == int(certConstr) or 0 == int(certConstr):
        certCont = certCont.split('-----END CERTIFICATE-----')[1]
        certCont += '-----END CERTIFICATE-----'
    #ps = sp.Popen(('echo', '-e', certCont), stdout=sp.PIPE)
    certObj = crypto.load_certificate(crypto.FILETYPE_PEM, certCont)
    if 0 == int(keyOnly):
        #ps = sp.Popen(('openssl', 'x509', '-outform', 'DER'), stdout=sp.PIPE, stdin=ps.stdout)
        ASN1 = crypto.dump_certificate(crypto.FILETYPE_ASN1, certObj)
    else:
        #ps = sp.Popen(('openssl', 'x509', '-pubkey', '-noout'), stdout=sp.PIPE, stdin=ps.stdout)
        #ps = sp.Popen(('openssl', 'pkey', '-pubin', '-outform', 'DER'), stdin=ps.stdout, stdout=sp.PIPE)
        pubKeyObj = certObj.get_pubkey()
        ASN1 = crypto.dump_publickey(crypto.FILETYPE_ASN1, pubKeyObj)
    if 1 == int(hashType):
        #output = sp.check_output(('openssl', 'sha256'), stdin=ps.stdout).split(b' ')[1].replace(b'\n',b'')
        output = hashlib.sha256(ASN1).hexdigest()
    elif 2 == int(hashType):
        #output = sp.check_output(('openssl', 'sha512'), stdin=ps.stdout).split(b' ')[1].replace(b'\n',b'')
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
