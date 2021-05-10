#!/usr/bin/env python
# -*- encoding: UTF8 -*-

import tlsarecgen

print(tlsarecgen.tlsaFromCertFile('fullchain.pem', 3,0,1))
print(tlsarecgen.tlsaFromCertFile('fullchain.pem', 3,1,1))
print(tlsarecgen.tlsaFromCertFile('fullchain.pem', 3,0,2))
print(tlsarecgen.tlsaFromCertFile('fullchain.pem', 3,1,2))
print(tlsarecgen.tlsaFromCertFile('fullchain.pem', 2,0,1))
print(tlsarecgen.tlsaFromCertFile('fullchain.pem', 2,1,1))
print(tlsarecgen.tlsaFromCertFile('fullchain.pem', 2,0,2))
print(tlsarecgen.tlsaFromCertFile('fullchain.pem', 2,1,2))




