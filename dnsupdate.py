#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from .inwxclient.inwx import domrobot 
from .simplelogger import simplelogger as log 
from .inwxwrapper import INWXwrapper
from .dnshelpers import createKeyDomainIfNotExists


inwxUserDict = {'default': 'user'}
inwxPasswdDict = {'default': 'passwd'}

try:
    from .passwords import *
except:
    log.info('no passwords.py file for dnsuptools default login')

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
    if type(dictList) is dict:
        dictList = [dictList]
    rvDictList = []
    for i, e in enumerate(dictList):
        extDict = dict(baseDict)
        extDict.update(dictList[i])
        rvDictList.append(extDict)
    return rvDictList

def matchUpperLabels(rv, filterDict):
    name = str(filterDict['name'])
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
    '''Class allows updating zone entries'''
    def __init__(self):
        self.handler = None
        self.defaultTTL = 600 

    def setHandler(self, handler):
        if type(handler) is str:
            if 'inwx' == handler:
                self.setHandler(INWXwrapper())
            return
        self.handler = handler


    def qry(self, filterDict):
        if type(filterDict) is list:
            self.__rv = [self.qry(e) for e in filterDict]
            return self.__rv
        log.debug(filterDict)
        createKeyDomainIfNotExists(filterDict)
        self.__rv = self.handler.info(filterDict)
        log.debug(self.__rv)
        return self.__rv

    def qryWild(self, filterDict, filterFunc = matchUpperLabels):
        if type(filterDict) is list:
            self.__rv = [self.qryWild(e, filterFunc) for e in filterDict]
            return self.__rv
        #name = str(filterDict['name'])
        filterDictWithName = dict(filterDict)
        createKeyDomainIfNotExists(filterDict) 
        # -> because at least one key needed
        if 'name' in filterDict.keys():
            del filterDict['name']
        self.__rv = self.qry(filterDict)
        #return filterFunc(self.__rv, name)
        return filterFunc(self.__rv, filterDictWithName)

    def add(self, updateDict):
        if type(updateDict) is list:
            self.__rv = [self.add(e) for e in updateDict]
            return self.__rv
        if 'ttl' not in updateDict:
            updateDict['ttl'] = self.defaultTTL
        try:
            log.debug('createRecord {}'.format(updateDict))
            if 'id' not in updateDict:
                self.__rv = self.handler.create(updateDict)
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
        self.__rv = [self.delById(e) for e in deleteOnlyIds]
        log.debug(self.__rv)
        return self.__rv

    def delById(self, rrID):
        return self.handler.delete({'id': rrID})

    def upd(self, updateDict):
        if type(updateDict) is not list:
            updateDict = [updateDict]
        return [(self.handler.update(e), infoRecord(e, 'update'))[0] for e in updateDict if 'id' in e]


    # updates or adds records
    # id     in recordDict -> update
    # id not in recordDict -> add
    def updOrAdd(self, recordDict):
        self.__rv = self.upd(recordDict)
        self.__rv.extend(self.add(recordDict))
        return self.__rv

    def updOrAddDictList(self, baseRecord, updateDictWithId):
        recordDictList = defaultDictList(baseRecord, updateDictWithId)
        return self.updOrAdd(recordDictList)

    def update(self, baseRecord, updateDict):
        matchRv = self.qry(baseRecord)
        matchIds = set(flatten(extractIds(matchRv)))
        baseRecord.update(updateDict)
        if len(matchIds) > 0:
            baseRecord['id'] = list(matchIds)[0]
            del baseRecord['domain']
            log.debug('updateRecord {}'.format(baseRecord))
            infoRecord(baseRecord, 'update')
            self.__rv = self.handler.update(baseRecord)
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
        self.delDictList(baseRecord, [{}] if '*' in contentDelete else [{'content': e} for e in contentDelete], [{'content': e} for e in contentPreserve], wild)

    def delDictList(self, baseRecord, dictListDelete = [{}], dictListPreserve = [], wild = False):
        delList = defaultDictList(baseRecord, dictListDelete)
        presList = defaultDictList(baseRecord, dictListPreserve)
        self.delete(delList, presList, wild)

    def setDictList(self, baseRecord, dictListDelete = [{}], dictListAdd = [], wild = False):
        self.addDictList(baseRecord, dictListAdd)
        self.delDictList(baseRecord, dictListDelete, dictListAdd, wild)

    def setList(self, baseRecord, contentList, deleteWild = False):
        self.addList(baseRecord, contentList)
        self.delList(baseRecord, '*', contentList, deleteWild)


def infoRecord(recordDict, operation = 'add'):
    rrType = recordDict['type']
    v = recordDict['content'].split('v=')
    if 1 < len(v):
        v = v[1].split(';')[0].split(' ')[0].split('1')[0]
        rrType = v.upper()
    if 5 < len(recordDict['name']):
        if '_adsp.' == recordDict['name'][:6]:
            rrType = 'ADSP'
    if 'content' in recordDict:
        log.info('{} {} for {} : {}'.format(operation, rrType, recordDict['name'], recordDict['content']))
    else:
        log.info('{} {} for {}'.format(operation, rrType, recordDict['name']))

