#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from dnsupdate import *

import pycurl
from StringIO import StringIO
import re

def sanIPv4(x):
    return re.sub('[^0-9.]', '', x)

def sanIPv6(x):
    return re.sub('[^0-9:a-fA-F]', '', x)

def curlGet(url):
    buff = StringIO()
    c = pycurl.Curl()
    c.setopt(c.URL, str(url))
    c.setopt(c.WRITEDATA, buff)
    c.perform()
    c.close()
    return str(buff.getvalue())

def getIPv4():
    try:
        ipv4Str = curlGet('ipv4.icanhazip.com')
    except Exception as e:
        return None
    return sanIPv4(ipv4Str)

def getIPv6():
    try:
        ipv6Str = curlGet('ipv6.icanhazip.com')
    except Exception as e:
        return None
    return sanIPv6(ipv6Str)


class DNSUpTools(DNSUpdate):
    def __init__(self):
        DNSUpdate.__init__(self)

    def addA(self, name, a):
        self.addList({'name': name, 'type': 'A'}, a)

    def delA(self, name, aDelete = '*', aPreserve = []):
        self.delList({'name': name, 'type': 'A'}, aDelete, aPreserve)    

    def setA(self, name, a = None):
        if a is None:
            a = getIPv4()
        if a is None:
            return
        self.setList({'name': name, 'type': 'A'}, a)

    def addAAAA(self, name, aaaa):
        self.addList({'name': name, 'type': 'AAAA'}, aaaa)

    def delAAAA(self, name, aaaaDelete = '*', aaaaPreserve = []):
        self.delList({'name': name, 'type': 'AAAA'}, aaaaDelete, aaaaPreserve)    

    def setAAAA(self, name, aaaa = None):
        if aaaa is None:
            aaaa = getIPv6()
        if aaaa is None:
            return
        self.setList({'name': name, 'type': 'AAAA'}, aaaa)

    




