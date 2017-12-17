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
