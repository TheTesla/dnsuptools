#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from dnsupdate import *
from tlsarecgen import *
from dkimrecgen import *

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
    c.setopt(pycurl.CONNECTTIMEOUT, 4)
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
        if a is None or 'auto' == a:
            a = getIPv4()
        if a is None:
            return
        self.setList({'name': name, 'type': 'A'}, a)

    def addAAAA(self, name, aaaa):
        self.addList({'name': name, 'type': 'AAAA'}, aaaa)

    def delAAAA(self, name, aaaaDelete = '*', aaaaPreserve = []):
        self.delList({'name': name, 'type': 'AAAA'}, aaaaDelete, aaaaPreserve)    

    def setAAAA(self, name, aaaa = None):
        if aaaa is None or 'auto' == aaaa:
            aaaa = getIPv6()
        if aaaa is None:
            return
        self.setList({'name': name, 'type': 'AAAA'}, aaaa)

    def addMX(self, name, mx, prio = 10):
        self.addList({'name': name, 'type': 'MX', 'prio': prio}, mx)

    def delMX(self, name, mxDelete = '*', mxPreserve = [], prio = None):
        if prio is None:
            self.delList({'name': name, 'type': 'MX'}, mxDelete, mxPreserve)
        else:
            self.delList({'name': name, 'type': 'MX', 'prio': prio}, mxDelete, mxPreserve)

    def setMX(self, name, mx, prio = 10):
        self.setList({'name': name, 'type': 'MX', 'prio': prio}, mx)

    def addCNAME(self, name, cname):
        self.addList({'name': name, 'type': 'CNAME'}, cname)

    def delCNAME(self, name, cnameDelete = '*', cnamePreserve = []):
        self.delList({'name': name, 'type': 'CNAME'}, cnameDelete, cnamePreserve)

    def setCNAME(self, name, cname):
        self.setList({'name': name, 'type': 'CNAME'}, cname)

    def addTXT(self, name, txt):
        self.addList({'name': name, 'type': 'TXT'}, txt)

    def delTXT(self, name, txtDelete = '*', txtPreserve = []):
        self.delList({'name': name, 'type': 'TXT'}, txtDelete, txtPreserve)

    def setTXT(self, name, txt):
        self.setList({'name': name, 'type': 'TXT'}, txt)

    def addNS(self, name, ns):
        self.addList({'name': name, 'type': 'NS'}, ns)

    def delNS(self, name, nsDelete = '*', nsPreserve = []):
        self.delList({'name': name, 'type': 'NS'}, nsDelete, nsPreserve)

    def setNS(self, name, ns):
        self.setList({'name': name, 'type': 'NS'}, ns)

    def addTLSA(self, name, tlsa, port = '*', proto = 'tcp'):
        self.addList({'name': tlsaName(name, port, proto), 'type': 'TLSA'}, tlsa)

    def delTLSA(self, name, tlsaDelete = '*', tlsaPreserve = [], port = '', proto = ''):
        self.delList({'name': tlsaName(name, port, proto), 'type': 'TLSA'}, tlsaDelete, tlsaPreserve)

    def setTLSA(self, name, tlsa, port = '*', proto = 'tcp'):
        self.setList({'name': tlsaName(name, port, proto), 'type': 'TLSA'}, tlsa, True)

    def addTLSAfromCert(self, name, certFilenames, tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]): 
        if type(tlsaTypes) is str:
            if 'auto' == tlsaTypes:
                tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]
        self.addTLSA(name, tlsaRecordsFromCertFile(certFilenames, tlsaTypes))

    def delTLSApreserveFromCert(self, name, tlsaDelete = '*', certFilenamesPreserve = []):
        self.delTLSA(name, tlsaDelete, tlsaRecordsFromCertFile(certFilenamesPreserve))

    def setTLSAfromCert(self, name, certFilenames, tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]): 
        if type(tlsaTypes) is str:
            if 'auto' == tlsaTypes:
                tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]
        self.setTLSA(name, tlsaRecordsFromCertFile(certFilenames, tlsaTypes))

    def addSPF(self, name, spf, v = 'spf1'):
        self.addTXT(name, 'v=%s %s' % (v, spf))

    def delSPF(self, name, spfDelete = '*', v = 'spf1', spfPreserve = []):
        if '*' == str(spfDelete):
            self.delTXT(name)
        else:
            self.delTXT(name, 'v=%s %s' % (v, spfDelete), spfPreserve)

    def setSPF(self, name, spf, v = 'spf1'):
        self.setTXT(name, 'v=%s %s' % (v, spf))

    def addADSP(self, name, adsp):
        self.addList({'name': '_adsp._domainkey.' + str(name), 'type': 'TXT'}, 'dkim=' + str(adsp))
    
    def delADSP(self, name, adspDelete = '*', adspPreserve = []):
        if '*' == adspDelete:
            self.delTXT('_adsp._domainkey.' + str(name), '*', adspPreserve)
        else:
            self.delTXT('_adsp._domainkey.' + str(name), 'dkim=' + str(adspDelete), adspPreserve)
    
    def setADSP(self, name, adsp):
        self.setList({'name': '_adsp._domainkey.' + str(name), 'type': 'TXT'}, 'dkim=' + str(adsp))
    
    def addDKIM(self, name, p, keyname = 'key1', v = 'DKIM1', k = 'rsa'):
        self.addTXT(str(keyname) + '._domainkey.' + str(name), 'v=%s; k=%s; p=%s' % (v, k, p)) 

    def addDKIMfromFile(self, name, filenames):
        if type(filenames) is list:
            for f in filenames:
                self.addDKIMfromFile(name, f)
        n, v, k, p = dkimFromFile(filenames)
        self.addDKIM(name, p, n, v, k)

    def delDKIM(self, name, keynames = '*', keynamesPreserve = []):
        if type(keynames) is str:
            keynames = [keynames]
        if type(keynamesPreserve) is str:
            keynamesPreserve = [keynamesPreserve]
        if '*' in keynamesPreserve:
            return
        if '*' in keynames:
            delete = [{'name': '_domainkey.' + str(name), 'type': 'TXT'}]
        else:
            delete = [{'name': str(e) + '._domainkey.' + str(name), 'type': 'TXT'} for e in keynames]
        preserve = [{'name': str(e) + '._domainkey.' + str(name)} for e in keynamesPreserve]
        self.delete(delete, preserve, True)

    def delDKIMpreserveFromFile(self, name, filenames):
        if type(filenames) is str:
            filenames = [filenames]
        keynamesPreserve = []
        for f in filenames:
            keynamesPreserve.append(delDKIMpreserveFromFile(f)[0])
        self.delDKIM(name, '*', keynamesPreserve)

    def setDKIM(self, name, p, keyname = 'key1', v = 'DKIM1', k = 'rsa'):
        self.addDKIM(name, p, keyname, v, k)
        self.delDKIM(name, '*', keyname)
    
    def setDKIMfromFile(self, name, filenames):
        self.addDKIMfromFile(name, filenames)
        self.delDKIMpreserveFromFile(name, filenames)


