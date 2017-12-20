#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from subprocess import *

def tlsaFromCertFile(certFilename, certConstr = 3, keyOnly = 0, hashType = 1):
    certCont = check_output(('cat', str(certFilename)))
    if 2 == certConstr or 0 == certConstr:
        certCont = certCont.split('-----END CERTIFICATE-----')[1] 
        certCont += '-----END CERTIFICATE-----'
    ps = Popen(('echo', '-e', certCont), stdout=PIPE)
    if 0 == keyOnly:
        ps = Popen(('openssl', 'x509', '-outform', 'DER'), stdout=PIPE, stdin=ps.stdout)
    else:
        ps = Popen(('openssl', 'x509', '-pubkey', '-noout'), stdout=PIPE, stdin=ps.stdout)
        ps = Popen(('openssl', 'pkey', '-pubin', '-outform', 'DER'), stdin=ps.stdout, stdout=PIPE)
    if 1 == hashType:
        output = check_output(('openssl', 'sha256'), stdin=ps.stdout)
    elif 2 == hashType:
        output = check_output(('openssl', 'sha512'), stdin=ps.stdout)
    ps.wait()
    return output.split(' ')[1]

def tlsaRecordsFromCertFile(certFilenames, tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]): 
    if type(certFilenames) is list:
        tlsaList = []
        for e in certFilenames:
            tlsaList.extend(tlsaRecordsFromCertFile(e, tlsaTypes))
        return tlsaList
    for tlsaType in tlsaTypes:
        tlsaList.append('%s %s %s %s' % (tlsaType[0], tlsaType[1], tlsaType[2], tlsaFromCertFile(certFilename, tlsaType[0], tlsaType[1], tlsaType[2])))
    return tlsaList



