#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from .inwxclient.inwx import domrobot 
from .simplelogger import simplelogger as log 

inwxUserDict = {'default': 'user'}
inwxPasswdDict = {'default': 'passwd'}

try:
    from .passwords import *
except:
    log.info('no passwords.py file for dnsuptools default login')

def createKeyDomainIfNotExists(d):
    log.debug(d)
    if 'name' not in d.keys():
        return
    if 'domain' not in d.keys():
        d['domain'] = '.'.join(d['name'].split('.')[-2:])

def extractIds(rv):
    if type(rv) is list:
        return [extractIds(e) for e in rv]
    if 'resData' in rv:
        if 'record' in rv['resData']:
            return [extractIds(e) for e in rv['resData']['record']]
        else:
            return []
    log.debug(rv)
    return rv['id']

def flatgen(x):
    if type(x) is list:
        for e in x:
            for f in flatgen(e):
                yield f
    else:
        yield x

def flatten(x):
    return [e for e in flatgen(x)]

def defaultDictList(baseDict, dictList):
    if dictList is dict:
        dictList = [dictList]
    rvDictList = []
    for i, e in enumerate(dictList):
        extDict = dict(baseDict)
        extDict.update(dictList[i])
        rvDictList.append(extDict)
    return rvDictList

def matchUpperLabels(rv, name):
    records = []
    if 'record' not in rv['resData']:
        return rv
    for i, record in enumerate(rv['resData']['record']):
        if name.count('.') > record['name'].count('.'):
            continue
        elif record['name'].split('.', record['name'].count('.') - name.count('.'))[-1] == name:
            records.append(record)
    rv['resData']['record'] = records
    return rv


class DNSUpdate:
    '''Class allows updating inwx zone entries'''
    def __init__(self):
        global inwxUserDict
        global inwxPasswdDict
        self.__apiUrl = 'https://api.domrobot.com/xmlrpc/'
        self.__conn = None
        self.__userDict = {'default': 'user'}
        self.__passwdDict = {'default': 'passwd'}
        self.__rv = None
        self.__isOpened = ''
        self.defaultTTL = 600 
        self.setUserDict(inwxUserDict)
        self.setPasswdDict(inwxPasswdDict)

    def setApiUrl(self, apiUrl):
        self.__apiUrl = apiUrl

    def setUser(self, user, domain = 'default'):
        self.__userDict[str(domain)] = user

    def setUserDict(self, userDict):
        self.__userDict = userDict

    def setPasswd(self, passwd, domain = 'default'):
        self.__passwdDict[str(domain)] = passwd

    def setPasswdDict(self, passwdDict):
        self.__passwdDict = passwdDict

    def getPasswd(self, domain):
        domain = str(domain)
        if domain not in self.__passwdDict.keys():
            domain = 'default'
        return self.__passwdDict[domain]

    def getUser(self, domain):
        domain = str(domain)
        if domain not in self.__userDict.keys():
            domain = 'default'
        return self.__userDict[domain]

    def __open(self, domain):
        if self.__isOpened == domain:
            return
        self.__conn = domrobot(self.__apiUrl, False)
        self.__rv = self.__conn.account.login({'lang': 'en', 'user': self.getUser(domain), 'pass': self.getPasswd(domain)})
        if 1000 != self.__rv['code']:
            return
        self.__isOpened = domain

    def close(self):
        self.__isOpened = ''

    def qry(self, filterDict):
        if type(filterDict) is list:
            self.__rv = [self.qry(e) for e in filterDict]
            return self.__rv
        createKeyDomainIfNotExists(filterDict)
        if 'domain' in filterDict:
            self.__open(filterDict['domain'])
        log.debug(filterDict)
        self.__rv = self.__conn.nameserver.info(filterDict)
        log.debug(self.__rv)
        return self.__rv

    def qryWild(self, filterDict, filterFunc = matchUpperLabels):
        if type(filterDict) is list:
            self.__rv = [self.qryWild(e, filterFunc) for e in filterDict]
            return self.__rv
        createKeyDomainIfNotExists(filterDict)
        name = str(filterDict['name'])
        if 'name' in filterDict.keys():
            del filterDict['name']
        self.__rv = self.qry(filterDict)
        return filterFunc(self.__rv, name)

    def add(self, updateDict):
        if type(updateDict) is list:
            self.__rv = [self.add(e) for e in updateDict]
            return self.__rv
        createKeyDomainIfNotExists(updateDict)
        self.__open(updateDict['domain'])
        if 'ttl' not in updateDict:
            updateDict['ttl'] = self.defaultTTL
        try:
            log.debug('createRecord {}'.format(updateDict))
            self.__rv = self.__conn.nameserver.createRecord(updateDict)
            infoRecord(updateDict, 'add (new)')
            log.debug(self.__rv)
        except Exception as e:
            if 1 < len(e.args):
                self.__rv = e.args[1]
            else:
                self.__rv = e.args
            if 2302 == self.__rv['code']:
                infoRecord(updateDict, 'add (exists)')
            log.debug(self.__rv)
        return self.__rv

    def delete(self, deleteDict, preserveDict = [], wild = False):
        if wild is True:
            deleteRv = self.qryWild(deleteDict)
            preserveRv = self.qryWild(preserveDict)
        elif callable(wild):
            deleteRv = self.qryWild(deleteDict, wild)
            preserveRv = self.qryWild(preserveDict, wild)
        else:
            deleteRv = self.qry(deleteDict)
            preserveRv = self.qry(preserveDict)
        log.debug(deleteRv)
        return self.deleteRv(deleteRv, preserveRv)

    def deleteRv(self, deleteRv, preserveRv = []):
        deleteIds = set(flatten(extractIds(deleteRv)))
        preserveIds = set(flatten(extractIds(preserveRv)))
        deleteOnlyIds = deleteIds - preserveIds
        log.debug('deleteRecords {}'.format(deleteOnlyIds))
        for e in deleteOnlyIds:
            rr = self.qry({'recordId': e})
            infoRecord(rr['resData']['record'][0], 'delete')
        self.__rv = [self.__conn.nameserver.deleteRecord({'id': e}) for e in deleteOnlyIds]
        log.debug(self.__rv)
        return self.__rv

    def delById(self, rrID):
        return self.__conn.nameserver.deleteRecord({'id': rrID})

    def updById(self, baseRecord, updateDict, rrID):
        baseRecord = dict(baseRecord)
        baseRecord.update(updateDict)
        if rrID is None:
            self.add(baseRecord)
            return
        baseRecord['id'] = rrID
        log.debug('updateRecord {}'.format(baseRecord))
        infoRecord(baseRecord, 'update')
        self.__rv = self.__conn.nameserver.updateRecord(baseRecord)
        log.debug(self.__rv)
        return self.__rv

    def update(self, baseRecord, updateDict):
        matchRv = self.qry(baseRecord)
        matchIds = set(flatten(extractIds(matchRv)))
        baseRecord.update(updateDict)
        if len(matchIds) > 0:
            baseRecord['id'] = list(matchIds)[0]
            del baseRecord['domain']
            log.debug('updateRecord {}'.format(baseRecord))
            infoRecord(baseRecord, 'update')
            self.__rv = self.__conn.nameserver.updateRecord(baseRecord)
            log.debug(self.__rv)
        else:
            self.__rv = self.add(baseRecord)
        return self.__rv

    def addList(self, baseRecord, contentList):
        if type(contentList) is not list:
            contentList = [contentList]
        self.addDictList(baseRecord, [{'content': e} for e in contentList])

    def addDictList(self, baseRecord, dictList):
        addList = defaultDictList(baseRecord, dictList)
        self.add(addList)
    
    def delList(self, baseRecord, contentDelete = '*', contentPreserve = [], wild = False):
        if type(contentDelete) is str:
            contentDelete = [contentDelete]
        if '*' in contentDelete:
            delList = baseRecord
        else:
            delList = defaultDictList(baseRecord, [{'content': e} for e in contentDelete])
        presList = defaultDictList(baseRecord, [{'content': e} for e in contentPreserve])
        log.debug(delList)
        log.debug(presList)
        self.delete(delList, presList, wild)

    def delDictList(self, baseRecord, dictListDelete = [{}], dictListPreserve = [], wild = False):
        delList = defaultDictList(baseRecord, dictListDelete)
        presList = defaultDictList(baseRecord, dictListPreserve)
        self.delete(delList, presList, wild)

    def setDictList(self, baseRecord, dictListDelete = [{}], dictListAdd = [], wild = False):
        self.addDictList(baseRecord, dictListAdd)
        self.delDictList(baseRecord, dictListDelete, dictListAdd, wild)

    # this may be not usefull, because of update id association on multiple matches:
    #def updDictList(self, baseRecord, dictListDelete = [{}], dictListUpd = [], wild = False):
    #    pass


    def setList(self, baseRecord, contentList, deleteWild = False):
        self.addList(baseRecord, contentList)
        self.delList(baseRecord, '*', contentList, deleteWild)


def infoRecord(recordDict, operation = 'add'):
    rrType = recordDict['type']
    v = recordDict['content'].split('v=')
    if 1 < len(v):
        v = v[1].split(';')[0].split(' ')[0].split('1')[0]
        rrType = v.upper()
    if 'content' in recordDict:
        log.info('{} {} for {} : {}'.format(operation, rrType, recordDict['name'], recordDict['content']))
    else:
        log.info('{} {} for {}'.format(operation, rrType, recordDict['name']))

