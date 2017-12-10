#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from dnsuptools import *


dnsut = DNSUpTools()

dnsut.addA('test42.entroserv.de', ['1.2.3.4', '5.6.7.8'])

dnsut.delA('test42.entroserv.de', '*', ['1.2.3.4', '9.8.7.6'])

