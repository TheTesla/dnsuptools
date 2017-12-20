#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from dnsuptools import *


dnsut = DNSUpTools()

print(dnsut.qryWild([{'name': 'testserver.entroserv.de'}, {'name': 'testserver.smartrns.net'}]))


dnsut.addA('test42.entroserv.de', ['1.2.3.4', '5.6.7.8'])

dnsut.delA('test42.entroserv.de', '*', ['1.2.3.4', '9.8.7.6'])

dnsut.setA('dynamic.entroserv.de')
dnsut.setAAAA('dynamic.entroserv.de')

dnsut.setDKIM('dynamic.entroserv.de', '12ea212', 'key42')
dnsut.setDKIM('dynamic.entroserv.de', '27182af', 'key23')
dnsut.delDKIM('dynamic.entroserv.de', '*', 'key23')
dnsut.addTLSAfromCert('dynamic.entroserv.de', 'fullchain.pem')


