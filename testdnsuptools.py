#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from dnsuptools import *


dnsut = DNSUpTools()

#print(dnsut.qryWild([{'name': 'testserver.entroserv.de'}, {'name': 'testserver.smartrns.net'}]))

#print(dnsut.qry({'name':'entroserv.de'}))

#dnsut.addA('test42.entroserv.de', ['1.2.3.4', '5.6.7.8'])

#dnsut.delA('test42.entroserv.de', '*', ['1.2.3.4', '9.8.7.6'])

#dnsut.setA('dynamic.entroserv.de')
#dnsut.setAAAA('dynamic.entroserv.de')
print(dnsut.qryWild({'name': 'mysrv.entroserv.de'}))
print(dnsut.qrySOA('entroserv.de'))
dnsut.setSOAentry('entroserv.de', {'ncttl': 3603})
dnsut.setDMARCentry('dynamic.entroserv.de', {'sp': 'test'})
dnsut.setSPF('dynamic.entroserv.de', ['mx','?all','aaaa','a'])
dnsut.setSPFentry('dynamic.entroserv.de', ['ip4:1.2.3.4','ip6:[ff:ff]'])
dnsut.setADSP('dynamic.entroserv.de', 'all')
dnsut.addCAA('dynamic.entroserv.de', {'flag': 128, 'tag': 'issue', 'url': 'letsdecrypt.org'})
print('qrySPF')
print(dnsut.qrySPF('dynamic.entroserv.de'))

dnsut.setSRV('dynamic.entroserv.de', {'port': 443, 'prio': 142, 'weight': 123, 'proto': 'tcp', 'service': 'https', 'server': 'dyn.entroserv.de'})
print(dnsut.qrySRV('dynamic.entroserv.de'))
#dnsut.setDKIM('dynamic.entroserv.de', '12ea212', 'key42')
#dnsut.setDKIM('dynamic.entroserv.de', '27182af', 'key23')
#dnsut.delDKIM('dynamic.entroserv.de', '*', 'key23')
#dnsut.addTLSAfromCert('dynamic.entroserv.de', 'fullchain.pem')


