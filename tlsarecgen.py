#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from subprocess import *

def tlsaFromCertFile(certFilename, keyOnly = 0, hashType = 1):
    if 0 == keyOnly:
        ps = Popen(('openssl', 'x509', '-in', str(certFilename), '-outform', 'DER'), stdout=PIPE)
    else:
        ps = Popen(('openssl', 'x509', '-in', str(certFilename), '-pubkey', '-noout'), stdout=PIPE)
        ps.wait()
        ps = Popen(('openssl', 'pkey', '-pubin', '-outform', 'DER'), stdin=ps.stdout, stdout=PIPE)
    if 1 == hashType:
        output = check_output(('openssl', 'sha256'), stdin=ps.stdout)
    elif 2 == hashType:
        output = check_output(('openssl', 'sha512'), stdin=ps.stdout)
    ps.wait()
    return output
