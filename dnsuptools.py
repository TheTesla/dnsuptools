#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from dnsupdate import *
from tlsarecgen import *
from dkimrecgen import *

import pycurl
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import re

import socket
import dns.resolver

def parseSPFentries(entryList):
    entryDict = {}
    for e in entryList:
        if e[0] in '+-~?':
            entryDict[e[1:]] = e[0]
        else:
            entryDict[e] = ''
    return entryDict
    
def formatSPFentries(entryDict):
    allVal = []
    if 'all' in entryDict:
        allVal = [str(entryDict['all'])+'all']
        del entryDict['all']
    entryList = ['{v}{k}'.format(v=v,k=k) for k, v in entryDict.items()]
    entryList.extend(allVal)
    return entryList

def qryDNS(nsName, qryName, recType):
    resolver = dns.resolver.Resolver()
    resolver.nameservers=[socket.gethostbyname(nsName)]
    return [rdata for rdata in resolver.query(qryName, recType)]

def parseDMARC(dmarcStr):
    return {e.split('=')[0].replace(' ',''): e.split('=')[1].replace(' ','') for e in dmarcStr.split(';')}

def formatDMARC(dmarcDict):
    v = 'v={v}'.format(v=dmarcDict['v'])
    del dmarcDict['v']
    return ';'.join([v] + ['{k}={v}'.format(k=k, v=v) for k, v in dmarcDict.items()])


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

def getIPv4(a = 'auto'):
    if 'auto' != a:
        return a
    try:
        ipv4Str = curlGet('ipv4.icanhazip.com')
    except Exception as e:
        return None
    return sanIPv4(ipv4Str)

def getIPv6(aaaa = 'auto'):
    if 'auto' != aaaa:
        return aaaa
    try:
        ipv6Str = curlGet('ipv6.icanhazip.com')
        print(ipv6Str)
    except Exception as e:
        return None
    return sanIPv6(ipv6Str)

def genSPF(spf, behavior = '?all', v = 'spf1'):
    if type(spf) is str:
        spf = [spf]
    if v is not None:
        spf = ['v=' + v] + spf
    if behavior is not None:
        spf += [behavior]
    return ' '.join(spf)

def genCAA(caaDict):
    if type(caaDict) is dict:
        caaDict = [caaDict]
    caaList = []
    for e in caaDict:
        caa = {'flag': 0, 'tag': 'issue'}
        caa.update(e)
        caaStr = '{x[flag]} {x[tag]} "{x[url]}"'.format(x=caa)
        caaList.append(caaStr)
    return caaList

def encDNSemail(x):
    xSpl = x.split('@')
    print(xSpl)
    if 1 == len(xSpl):
        return x
    elif 1 < len(xSpl):
        return xSpl[0].replace('.', '\\.') + '.' + xSpl[1] + '.'
    else:
        raise(TypeError('No valid email address'))

def decDNSemail(x):
    if 2 == len(x.split('@')):
        return x
    elif 2 < len(x.split('@')):
        raise(TypeError('No valid email address'))
    else:
        xSpl = x.split('\\.')
        y = '.'.join(xSpl[:-1]) + '.' + '@'.join(xSpl[-1].split('.', 1))
        if '.' == y[0]:
            y = y[1:]
        if '.' == y[-1]:
            return y[:-1]
        else:
            return y

def makeIP4(a):
    if a is None:
        a = 'auto'
    if type(a) is not list:
        a = [a]
    a = [getIPv4(e) for e in a]
    a = [e for e in a if e is not None]
    return a

def makeIP6(aaaa):
    if aaaa is None:
        aaaa = 'auto'
    if type(aaaa) is not list:
        aaaa = [aaaa]
    print(aaaa)
    aaaa = [getIPv6(e) for e in aaaa]
    aaaa = [e for e in aaaa if e is not None]
    print(aaaa)
    return aaaa


class DNSUpTools(DNSUpdate):
    def __init__(self):
        DNSUpdate.__init__(self)

    def qrySOA(self, name):
        soa = self.qry({'name': name, 'type': 'SOA'})['resData']['record'][0]
        soaList = soa['content'].split(' ')
        soa = qryDNS(soaList[0], name, 'SOA')[0] # extended query for last 4 values - WARNING internal nameserver update takes time, consecutive updates may result in inconsistencies
        return {'primns': soa.mname.to_text(), 'hostmaster': decDNSemail(soa.rname.to_text()), 'serial': soa.serial, 'refresh': soa.refresh, 'retry': soa.retry, 'expire': soa.expire, 'ncttl': soa.minimum}

    def setSOAentry(self, name, updSOAdict):
        soa = self.qrySOA(name)
        soa.update(updSOAdict)
        soa['serial'] += 1
        soa['hostmaster'] = encDNSemail(soa['hostmaster'])
        soaTXT = '{soa[primns]} {soa[hostmaster]} {soa[serial]} {soa[refresh]} {soa[retry]} {soa[expire]} {soa[ncttl]}'.format(soa = soa)
        self.update({'name': name, 'type': 'SOA'}, {'content': soaTXT})

    def addA(self, name, a = 'auto'):
        a = makeIP4(a)
        self.addList({'name': name, 'type': 'A'}, a)

    def delA(self, name, aDelete = '*', aPreserve = []):
        self.delList({'name': name, 'type': 'A'}, aDelete, aPreserve)

    def setA(self, name, a = 'auto'):
        a = makeIP4(a)
        self.setList({'name': name, 'type': 'A'}, a)

    def addAAAA(self, name, aaaa):
        aaaa = makeIP6(aaaa)
        self.addList({'name': name, 'type': 'AAAA'}, aaaa)

    def delAAAA(self, name, aaaaDelete = '*', aaaaPreserve = []):
        self.delList({'name': name, 'type': 'AAAA'}, aaaaDelete, aaaaPreserve)

    def setAAAA(self, name, aaaa = 'auto'):
        aaaa = makeIP6(aaaa)
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
        if 'auto' == str(tlsaTypes):
            tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]
        print('name = %s' % name)
        print('certFilenames = %s' % certFilenames)
        self.addTLSA(name, tlsaRecordsFromCertFile(certFilenames, tlsaTypes))

    def delTLSApreserveFromCert(self, name, tlsaDelete = '*', certFilenamesPreserve = []):
        self.delTLSA(name, tlsaDelete, tlsaRecordsFromCertFile(certFilenamesPreserve))

    def setTLSAfromCert(self, name, certFilenames, tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]): 
        if 'auto' == str(tlsaTypes):
            tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]
        self.setTLSA(name, tlsaRecordsFromCertFile(certFilenames, tlsaTypes))

    #def addSPF(self, name, spf, behavior = '?all', v = 'spf1'):
    #    txt = genSPF(spf, behavior, v)
    #    self.addTXT(name, txt)

    def setSPFentry(self, name, spf):
        rrQ = self.qrySPF(name)
        spfQ = rrQ[0]['content'].split(' ')
        spfD = parseSPFentries(spfQ[1:])
        spfD.update(parseSPFentries(spf))
        spfL = formatSPFentries(spfD)
        self.setSPF(name, spfL, spfQ[0][2:])

    def qrySPF(self, name):
        rv = self.qry({'name': str(name), 'type': 'TXT'})
        if 'record' not in rv['resData']:
            return []
        return [rr for rr in rv['resData']['record'] if 'v=spf1' in rr['content'].split(' ')]


    def delSPF(self, name, spfDelete = '*', v = 'spf1', spfPreserve = []):
        if '*' == str(spfDelete):
            self.delTXT(str(name))
        else:
            self.delTXT(str(name), 'v=%s %s' % (v, spfDelete), spfPreserve)

    def setSPF(self, name, spf, v = 'spf1'):
        print(spf)
        print(parseSPFentries(spf))
        print(formatSPFentries(parseSPFentries(spf)))
        spf = ' '.join(formatSPFentries(parseSPFentries(spf)))
        print(spf)
        txt = genSPF(spf, None, v)
        print(txt)
        self.update({'name': str(name), 'type': 'TXT'}, {'content': txt})

    def delDMARC(self, name):
        self.delTXT('_dmarc.'+str(name))

    def setDMARC(self, name, dmarcDict):
        dmarc = {'v': 'DMARC1', 'p': 'none'}
        dmarc.update(dmarcDict)
        dmarc = {k: v for k, v in dmarc.items() if '' != v}
        dmarcStr = formatDMARC(dmarc)
        self.update({'name': '_dmarc.'+str(name), 'type': 'TXT'}, {'content': dmarcStr})

    def qryDMARC(self, name):
        dmarcRv = self.qry({'name': '_dmarc.'+str(name), 'type': 'TXT'})
        dmarcQ = []
        if 'record' in dmarcRv['resData']:
            dmarcQ = [parseDMARC(rr['content']) for rr in dmarcRv['resData']['record']]
        return dmarcQ

    def setDMARCentry(self, name, dmarcDict):
        q = self.qryDMARC(name)
        dmarc = {}
        for e in q:
            dmarc.update(e)
        dmarc.update(dmarcDict)
        self.setDMARC(name, dmarc) 



    def addADSP(self, name, adsp):
        self.addList({'name': '_adsp._domainkey.' + str(name), 'type': 'TXT'}, 'dkim=' + str(adsp))

    def delADSP(self, name, adspDelete = '*', adspPreserve = []):
        if '*' == adspDelete:
            self.delTXT('_adsp._domainkey.' + str(name), '*', adspPreserve)
        else:
            self.delTXT('_adsp._domainkey.' + str(name), 'dkim=' + str(adspDelete), adspPreserve)

    def setADSP(self, name, adsp):
        self.update({'name': '_adsp._domainkey.' + str(name), 'type': 'TXT'}, {'content': 'dkim=' + str(adsp)})
        #self.setList({'name': '_adsp._domainkey.' + str(name), 'type': 'TXT'}, 'dkim=' + str(adsp))

    def addCAA(self, name, caaDict):
        self.addList({'name': str(name), 'type': 'CAA'}, genCAA(caaDict))

    def setCAA(self, name, caaDict):
        self.setList({'name': str(name), 'type': 'CAA'}, genCAA(caaDict))

    def delCAA(self, name):
        self.setCAA(name, [])

    def addSRV(self, name, srvDict):
        print(srvDict)
        if type(srvDict) is dict:
            srvDict = [srvDict]
        for e in srvDict:
            srv = {'prio': 10, 'weight' : 0}
            srv.update(e)
            self.addList({'name': '_{x[service]}._{x[proto]}.{name}'.format(x=srv, name=str(name)), 'type': 'SRV', 'prio': srv['prio']}, '{x[weight]} {x[port]} {x[server]}'.format(x=srv))

    def qrySRV(self, name, srvDict = {}):
        qryName = ''
        srv = {'type': 'SRV', 'name': name}
        srvRv = self.qryWild(srv)
        if type(srvDict) is dict:
            srvDict = [srvDict]
        resultList = []
        for srvEntry in srvDict:
            result = []
            for srvRR in srvRv['resData']['record']:
                srvRR['weight'], srvRR['port'], srvRR['server'] = srvRR['content'].split(' ')
                service, proto = srvRR['name'].split('.')[:2]
                srvRR['service'] = service[1:]
                srvRR['proto'] = proto[1:]
                if 'port' in srvDict:
                    if srvDict['port'] != srvRR['port']:
                        continue
                if 'proto' in srvDict:
                    if srvDict['proto'] != srvRR['proto']:
                        continue
                if 'service' in srvDict:
                    if srvDict['service'] != srvRR['service']:
                        continue
                if 'prio' in srvDict:
                    if srvDict['prio'] != srvRR['prio']:
                        continue
                if 'weight' in srvDict:
                    if srvDict['weight'] != srvRR['weight']:
                        continue
                result.append(srvRR)
            resultList.append(result)
        return resultList

    def delSRV(self, name, srvDelete, srvPreserve = []):
        deleteRv = self.qrySRV(name, srvDelete)
        preserveRv = self.qrySRV(name, srvPreserve)
        return self.deleteRv(deleteRv, preserveRv)

    def setSRV(self, name, srvDict):
        self.addSRV(name, srvDict)
        self.delSRV(name, {}, srvDict)


    def addDKIM(self, name, p, keyname = 'key1', v = 'DKIM1', k = 'rsa'):
        if k is None:
            k = 'rsa'
        if v is None:
            v = 'DKIM1'
        if keyname is None:
            keyname = 'key'
        if p is None:
            return
        self.addTXT(str(keyname) + '._domainkey.' + str(name), 'v=%s; k=%s; p=%s' % (v, k, p)) 

    def addDKIMfromFile(self, name, filenames):
        if type(filenames) is list:
            for f in filenames:
                self.addDKIMfromFile(name, f)
        else:
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
            keynamesPreserve.append(dkimFromFile(f)[0])
        self.delDKIM(name, '*', keynamesPreserve)

    def setDKIM(self, name, p, keyname = 'key1', v = 'DKIM1', k = 'rsa'):
        self.addDKIM(name, p, keyname, v, k)
        self.delDKIM(name, '*', keyname)

    def setDKIMfromFile(self, name, filenames):
        self.addDKIMfromFile(name, filenames)
        self.delDKIMpreserveFromFile(name, filenames)


