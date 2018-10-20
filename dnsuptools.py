#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from .dnsupdate import *
from .tlsarecgen import *
from .dkimrecgen import *
from simpleloggerplus import simpleloggerplus as log

import pycurl
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import socket
import dns.resolver

def dkimKeySplit(dkimDict):
    if type(dkimDict) is list:
        return [dkimKeySplit(e) for e in dkimDict]
    keyL = dkimDict['keyname'].split('_')
    dkimDict['keybasename'] = keyL[0]
    if 1 < len(keyL):
        dkimDict['keynbr'] = keyL[1]
    return dkimDict

def parseNSentry(record):
    return {'ns': record['content']}

def parseDKIMentry(record):
    key = record['name']
    keyList = key.split('.')
    val = record['content'].replace(' ', '')
    valList = val.split(';')
    valDict = {e.split('=')[0]: e.split('=')[1] for e in valList if '=' in e}
    dkim = {'keyname': keyList[0], 'dkimlabel': keyList[1]}
    dkim.update(valDict)
    dkimKeySplit(dkim)
    return dkim

def formatDKIMentry(name, dkimDict):
    if type(dkimDict) is list:
        return [formatDKIMentry(name, e) for e in dkimDict]
    dkim = {'keyname': 'key1', 'v': 'DKIM1', 'k': 'rsa'}
    dkim.update(dkimDict)
    return {'name': '{x[keyname]}._domainkey.{name}'.format(x=dkim, name=str(name)), 'type': 'TXT', 'content': 'v={x[v]}; k={x[k]}; p={x[p]}'.format(x=dkim)}


def parseTLSAentry(record):
    key = record['name']
    keyList = key.split('.')
    val = record['content']
    valList = val.split(' ')
    tlsa = {'port': keyList[0], 'proto': keyList[1], 'usage': valList[0], 'selector': valList[1], 'matchingtype': valList[2], 'tlsa': valList[3]}
    if '_' == tlsa['port'][0]:
        tlsa['port'] = tlsa['port'][1:]
    if '_' == tlsa['proto'][0]:
        tlsa['proto'] = tlsa['proto'][1:]
    tlsa['tlsa'] = tlsa['tlsa'].replace('\n','')
    return tlsa

def formatTLSAentry(name, tlsaDict):
    if type(tlsaDict) is list:
        return [formatTLSAentry(name, e) for e in tlsaDict]
    tlsa = {'port': '*', 'proto': 'tcp'}
    tlsa.update(tlsaDict)
    if '*' != tlsa['port']:
        tlsa['port'] = '_{}'.format(tlsa['port'])
    tlsa['tlsa'] = tlsa['tlsa'].replace('\n','')
    return {'name': '{x[port]}._{x[proto]}.{name}'.format(x=tlsa, name=str(name)), 'type': 'TLSA', 'content': '{x[usage]} {x[selector]} {x[matchingtype]} {x[tlsa]}'.format(x=tlsa)}


def parseSRVentry(record):
    key = record['name']
    keyList = key.split('.')
    val = record['content']
    valList = val.split(' ')
    srv = {'service': keyList[0][1:], 'proto': keyList[1][1:], 'weight': valList[0], 'port': valList[1], 'server': valList[2], 'prio': record['prio']}
    return srv

def formatSRVentry(name, srvDict):
    if type(srvDict) is list:
        return [formatSRVentry(name, e) for e in srvDict]
    srv = srvDict
    return {'name': '_{x[service]}._{x[proto]}.{name}'.format(x=srv, name=str(name)), 'type': 'SRV', 'prio': srv['prio'], 'content': '{x[weight]} {x[port]} {x[server]}'.format(x=srv)}


def isSubDict(subDict, contentDict):
    for k, v in subDict.items():
        if k not in contentDict:
            return False
        if str(v) != str(contentDict[k]):
            return False
    return True


def parseSPFentries(entryList):
    entryDict = {}
    for e in entryList:
        if e[0] in '+-~?':
            entryDict[e[1:]] = e[0]
        else:
            entryDict[e] = '+'
    return entryDict
    
def formatSPFentries(entryDict):
    allVal = []
    if 'all' in entryDict:
        allVal = [str(entryDict['all'])+'all']
        del entryDict['all']
    entryList = ['{v}{k}'.format(v=v,k=k) for k, v in entryDict.items()]
    entryList.extend(allVal)
    return entryList

def qryDNS(nsName, qryName, recType, ns=None):
    resolver = dns.resolver.Resolver()
    if ns is not None:
        if type(ns) is not list:
            ns = [ns]
        if 0 < len(ns):
            resolver.nameservers = ns
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
        log.debug(ipv6Str)
    except Exception as e:
        return None
    return sanIPv6(ipv6Str)

def genSPF(spf, behavior = '?all', v = 'spf1'):
    if type(spf) is str:
        spf = [spf]
    if type(spf) is set:
        spf = list(spf)
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

def parseCAA(caaRR):
    caaStr = caaRR['content']
    log.debug(caaStr)
    caa = {}
    caa['flag'], caa['tag'], caa['url'] = caaStr.split(' ')
    caa['url'] = caa['url'][1:-1]
    caa = {str(k): str(v) for k, v in caa.items()}
    log.debug(caa)
    return caa

def encDNSemail(x):
    xSpl = x.split('@')
    log.debug(xSpl)
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
    log.debug(aaaa)
    aaaa = [getIPv6(e) for e in aaaa]
    aaaa = [e for e in aaaa if e is not None]
    log.debug(aaaa)
    return aaaa


def soaUpdate(curSOAdict, updSOAdict):
    soa = dict(curSOAdict)
    soa.update(updSOAdict)
    soa['serial'] += 1
    soa['hostmaster'] = encDNSemail(soa['hostmaster'])
    soaTXT = '{soa[primns]} {soa[hostmaster]} {soa[serial]} {soa[refresh]} {soa[retry]} {soa[expire]} {soa[ncttl]}'.format(soa = soa)
    return {'content': soaTXT, 'id': soa['id']}

def soaQRYs2dict(soaNSqry, soaAPIqry):
    soa = soaNSqry
    return {'primns': soa.mname.to_text(), 'hostmaster': decDNSemail(soa.rname.to_text()), 'serial': soa.serial, 'refresh': soa.refresh, 'retry': soa.retry, 'expire': soa.expire, 'ncttl': soa.minimum, 'id': soaAPIqry['id']}


def recordFilter(entry, records, parser=None):
    result = []
    for rr in records:
        if parser is not None:
            rr.update(parser(rr))
        if not isSubDict(entry, rr):
            continue
        result.append(rr)
    return result
    

class DNSUpTools(DNSUpdate):
    def __init__(self):
        DNSUpdate.__init__(self)

    def qrySOA(self, name):
        soaAPI = self.qry({'name': name, 'type': 'SOA'})[0]
        soaList = soaAPI['content'].split(' ')
        ns = [e['content'] for e in self.qryNS(name)[0]]
        soaNS = qryDNS(soaList[0], name, 'SOA', ns)[0] # extended query for last 4 values - WARNING internal nameserver update takes time, consecutive updates may result in inconsistencies
        return soaQRYs2dict(soaNS, soaAPI)

    def setSOAentry(self, name, updSOAdict):
        soa = self.qrySOA(name)
        soaRR = soaUpdate(soa, updSOAdict)
        self.updOrAddDictList({'name': name, 'type': 'SOA'}, soaRR)

    def addA(self, name, a = 'auto'):
        a = makeIP4(a)
        self.addList({'name': name, 'type': 'A'}, a)

    def delA(self, name, aDelete = '*', aPreserve = []):
        aPreserve = makeIP4(aPreserve)
        self.delList({'name': name, 'type': 'A'}, aDelete, aPreserve)

    def setA(self, name, a = 'auto'):
        self.addA(name, a)
        self.delA(name, '*', a)

    def addAAAA(self, name, aaaa):
        aaaa = makeIP6(aaaa)
        self.addList({'name': name, 'type': 'AAAA'}, aaaa)

    def delAAAA(self, name, aaaaDelete = '*', aaaaPreserve = []):
        aaaaPreserve = makeIP6(aaaaPreserve)
        self.delList({'name': name, 'type': 'AAAA'}, aaaaDelete, aaaaPreserve)

    def setAAAA(self, name, aaaa = 'auto'):
        self.addAAAA(name, aaaa)
        self.delAAAA(name, '*', aaaa)

    def addMX(self, name, mx):
        self.addDictList({'name': name, 'type': 'MX', 'prio': 10}, mx)

    def delMX(self, name, mxDelete = [{}], mxPreserve = []):
        self.delDictList({'name': name, 'type': 'MX'}, mxDelete, mxPreserve)

    def setMX(self, name, mx):
        self.addMX(name, mx)
        self.delMX(name, [{}], mx)

    def addCNAME(self, name, cname):
        self.addList({'name': name, 'type': 'CNAME'}, cname)

    def delCNAME(self, name, cnameDelete = '*', cnamePreserve = []):
        self.delList({'name': name, 'type': 'CNAME'}, cnameDelete, cnamePreserve)

    def setCNAME(self, name, cname):
        self.addCNAME(name, cname)
        self.delCNAME(name, '*', cname)

    def addTXT(self, name, txt):
        self.addList({'name': name, 'type': 'TXT'}, txt)

    def delTXT(self, name, txtDelete = '*', txtPreserve = []):
        self.delList({'name': name, 'type': 'TXT'}, txtDelete, txtPreserve)

    def setTXT(self, name, txt):
        self.addTXT(name, txt)
        self.delTXT(name, '*', txt)

    def addNS(self, name, ns):
        self.addList({'name': name, 'type': 'NS'}, ns)

    def delNS(self, name, nsDelete = '*', nsPreserve = []):
        self.delList({'name': name, 'type': 'NS'}, nsDelete, nsPreserve)

    def qryNS(self, name):
        return self.qryRR(name, 'NS')


    def setNS(self, name, ns):
        self.addNS(name, ns)
        self.delNS(anme, '*', ns)

    def addTLSA(self, name, tlsaDict):
        tlsaDictList = tlsaFromFile(tlsaDict)
        tlsaRRdictList = formatTLSAentry(name, tlsaDictList)
        self.addDictList({}, tlsaRRdictList)

    def delTLSA(self, name, tlsaDelete={}, tlsaPreserve = []):
        if type(tlsaDelete) is dict:
            tlsaDelete = [tlsaDelete]
        if type(tlsaPreserve) is dict:
            tlsaPreserve = [tlsaPreserve]
        tlsaFromFile(tlsaDelete)
        tlsaFromFile(tlsaPreserve)
        for i, e in enumerate(tlsaDelete):
            if 'filename' in e:
                del tlsaDelete[i]['filename']
            if 'op' in e:
                del tlsaDelete[i]['op']
        for i, e in enumerate(tlsaPreserve):
            if 'filename' in e:
                del tlsaPreserve[i]['filename']
            if 'op' in e:
                del tlsaPreserve[i]['op']
        deleteRv = self.qryTLSA(name, tlsaDelete)
        preserveRv = self.qryTLSA(name, tlsaPreserve)
        return self.deleteRv(deleteRv, preserveRv)

    def setTLSA(self, name, tlsaDict):
        self.addTLSA(name, tlsaDict)
        self.delTLSA(name, {}, tlsaDict)

    def addTLSAfromCert(self, name, certFilenames, tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]):
        if 'auto' == str(tlsaTypes):
            tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]
        log.debug('name = %s' % name)
        log.debug('certFilenames = %s' % certFilenames)
        self.addTLSA(name, tlsaRecordsFromCertFile(certFilenames, tlsaTypes))

    def delTLSApreserveFromCert(self, name, tlsaDelete = {}, certFilenamesPreserve = []):
        self.delTLSA(name, tlsaDelete, tlsaRecordsFromCertFile(certFilenamesPreserve))

    def setTLSAfromCert(self, name, certFilenames, tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]): 
        if 'auto' == str(tlsaTypes):
            tlsaTypes = [[3,0,1], [3,0,2], [3,1,1], [3,1,2], [2,0,1], [2,0,2], [2,1,1], [2,1,2]]
        self.setTLSA(name, tlsaRecordsFromCertFile(certFilenames, tlsaTypes))

    def setSPFentry(self, name, spfADD, spfDEL = {}):
        if 0 == len(spfADD) and 0 == len(spfDEL):
            return
        rrQ = self.qrySPF(name)
        if 0 == len(rrQ):
            self.setSPF(name, parseSPFentries(set(spfADD)))
            return
        spfQ = rrQ[0]['content'].split(' ')
        spfID = rrQ[0]['id']
        spfSqry = set(spfQ[1:])
        spfSdel = set(spfDEL)
        if '*' in spfSdel:
            spfSqry = {}
        spfS = {e for e in spfSqry if e not in spfSdel}
        spfD = parseSPFentries(spfS)
        spfD.update(parseSPFentries(set(spfADD)))
        spfL = formatSPFentries(spfD)
        self.setSPF(name, spfL, spfID, spfQ[0][2:])



    def qrySPF(self, name):
        rv = self.qry({'name': str(name), 'type': 'TXT'})
        return [rr for rr in rv if 'v=spf1' in rr['content'].split(' ')]

    def delSPF(self, name):
        spf = qrySPF(name)
        self.setSPF(name, [], spf['id'])

    # only one SPF record allowed
    def setSPF(self, name, spf, rrID = None, v = 'spf1'):
        if 0 == len(spf):
            if rrID is None:
                return
            self.delById(rrID)
            return
        spf = ' '.join(formatSPFentries(parseSPFentries(spf)))
        txt = genSPF(spf, None, v)
        updR = {'content': txt}
        if rrID is not None:
            updR['id'] = rrID
        self.updOrAddDictList({'name': str(name), 'type': 'TXT'}, updR)

    def delDMARC(self, name):
        self.delTXT('_dmarc.'+str(name))
    
    # only one DMARC record allowed
    def setDMARC(self, name, dmarcDict):
        log.debug(dmarcDict)
        if {} == dmarcDict:
            self.delDMARC(name)
            return
        dmarc = {'v': 'DMARC1', 'p': 'none'}
        dmarc.update(dmarcDict)
        dmarc = {k: v for k, v in dmarc.items() if '' != v}
        dmarcStr = formatDMARC(dmarc)
        self.update({'name': '_dmarc.'+str(name), 'type': 'TXT'}, {'content': dmarcStr})

    def qryDMARC(self, name):
        dmarcRv = self.qry({'name': '_dmarc.'+str(name), 'type': 'TXT'})
        dmarcQ = [parseDMARC(rr['content']) for rr in dmarcRv]
        return dmarcQ

    def setDMARCentry(self, name, dmarcDict):
        q = self.qryDMARC(name)
        dmarc = {}
        for e in q:
            dmarc.update(e)
        if '' in dmarcDict:
            dmarc = dict(dmarcDict)
            del dmarc['']
        else:
            dmarc.update(dmarcDict)
        self.setDMARC(name, dmarc) 


    def delADSP(self, name, adspDelete = '*', adspPreserve = []):
        if '*' == adspDelete:
            self.delTXT('_adsp._domainkey.' + str(name), '*', adspPreserve)
        else:
            self.delTXT('_adsp._domainkey.' + str(name), 'dkim=' + str(adspDelete), adspPreserve)

    # only one ADSP record allowed
    def setADSP(self, name, adsp):
        if '' == adsp:
            self.delADSP(name)
            return
        self.update({'name': '_adsp._domainkey.' + str(name), 'type': 'TXT'}, {'content': 'dkim=' + str(adsp)})

    def setACME(self, name, challenge=''):
        if '' == challenge:
            self.delACME(name)
            return
        self.update({'name': '_acme-challenge.' + str(name), 'type': 'TXT'}, {'content': str(challenge)})

    def delACME(self, name):
        self.delTXT('_acme-challenge.' + str(name), '*')


    def addCAA(self, name, caaDict):
        self.addList({'name': str(name), 'type': 'CAA'}, genCAA(caaDict))

    def setCAA(self, name, caaDict):
        self.addCAA(name, caaDict)
        self.delCAA(name, [{}], caaDict)

    def qryCAA(self, name, caaDict = {}):
        if type(caaDict) is dict:
            caaDict = [caaDict]
        for e in caaDict:
            e['name'] = str(name)
        return self.qryRR(str(name), 'CAA', parseCAA, caaDict, [])

    def delCAA(self, name, caaDelete = [{}], caaPreserve = []):
        deleteRv = self.qryCAA(name, caaDelete)
        preserveRv = self.qryCAA(name, caaPreserve)
        return self.deleteRv(deleteRv, preserveRv)

    def addSRV(self, name, srvDict):
        log.debug(srvDict)
        srvDictList = defaultDictList({'prio': 10, 'weight' : 0}, srvDict)
        srvRRdictList = formatSRVentry(name, srvDictList)
        self.addDictList({}, srvRRdictList)

    def qryRR(self, name, rrType, parser=None, rrDict = {}, qryFilters=[MatchUpperLabels]):
        rrRv = self.qryWild({'name': name, 'type': rrType}, qryFilters)
        if type(rrDict) is dict:
            rrDict = [rrDict]
        return [recordFilter(e, rrRv, parser) for e in rrDict]

    def qryTLSA(self, name, tlsaDict = {}):
        #if type(tlsaDict) is dict:
        #    tlsaDict = [tlsaDict]
        #for e in tlsaDict:
        #    if 'tlsa' in e:
        #        e['tlsa'] = e['tlsa'].replace('\n','')
        return self.qryRR(name, 'TLSA', parseTLSAentry, tlsaDict)

    def qrySRV(self, name, srvDict = {}):
        return self.qryRR(name, 'SRV', parseSRVentry, srvDict)

    def delSRV(self, name, srvDelete, srvPreserve = []):
        deleteRv = self.qrySRV(name, srvDelete)
        preserveRv = self.qrySRV(name, srvPreserve)
        return self.deleteRv(deleteRv, preserveRv)

    def setSRV(self, name, srvDict):
        self.addSRV(name, srvDict)
        self.delSRV(name, {}, srvDict)

    def addDKIM(self, name, dkimDict):
        dkimDict = dkimFromFile(dkimDict)
        dkimRRdictList = formatDKIMentry(name, dkimDict)
        self.addDictList({}, dkimRRdictList)

    def addDKIMfromFile(self, name, filenames):
        if type(filenames) is str:
            filenames = [filenames]
        dkimDictList = [{'filename': e} for e in filenames]
        self.addDKIM(name, dkimDictList)

    def qryDKIM(self, name, dkimDict):
        rv = self.qryRR('_domainkey.{}'.format(name), 'TXT', parseDKIMentry, dkimDict)
        rv = [f for e in rv for f in e if f['keyname'] != '_adsp']
        return rv

    def delDKIM(self, name, dkimDelete = {}, dkimPreserve = []):
        if type(dkimDelete) is dict:
            dkimDelete = [dkimDelete]
        if type(dkimPreserve) is dict:
            dkimPreserve = [dkimPreserve]
        dkimFromFile(dkimDelete)
        dkimFromFile(dkimPreserve)
        for i, e in enumerate(dkimDelete):
            if 'filename' in e:
                del dkimDelete[i]['filename']
        for i, e in enumerate(dkimPreserve):
            if 'filename' in e:
                del dkimPreserve[i]['filename']
        deleteRv = self.qryDKIM(name, dkimDelete)
        preserveRv = self.qryDKIM(name, dkimPreserve)
        return self.deleteRv(deleteRv, preserveRv)

    def delDKIMpreserveFromFile(self, name, filenames):
        if type(filenames) is str:
            filenames = [filenames]
        dkimPreserveList = [{'filename': e} for e in filenames]
        self.delDKIM(name, {}, dkimPreserveList)


    def setDKIM(self, name, dkimDict):
        self.addDKIM(name, dkimDict)
        self.delDKIM(name, {}, dkimDict)

    def setDKIMfromFile(self, name, filenames):
        self.addDKIMfromFile(name, filenames)
        self.delDKIMpreserveFromFile(name, filenames)


