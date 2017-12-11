#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from inwxclient.inwx import domrobot, prettyprint, getOTP
from passwords import *

def createKeyDomainIfNotExists(d):
    if 'domain' not in d.keys():
        d['domain'] = '.'.join(d['name'].split('.')[-2:])

def extractIds(rv):
    if type(rv) is list:
        return [extractIds(e) for e in rv if 'record' in e['resData']]
    return [e['id'] for e in rv['resData']['record']]

def flatgen(x):
    if type(x) is list:
        for e in x:
            for f in flatgen(e):
                yield f
    else:
        yield x

def flatten(x):
    return [e for e in flatgen(x)]

def makeDictList(baseDict, entryName, entryList):
    if type(entryList) is not list:
        entryList = [entryList]
    dictList = []
    for e in entryList:
        extDict = dict(baseDict)
        extDict.update({str(entryName): e})
        dictList.append(extDict)
    return dictList

def matchUpperLabels(rv, name):
    records = []
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
        self.__open(filterDict['domain'])
        self.__rv = self.__conn.nameserver.info(filterDict)
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
        try:
            self.__rv = self.__conn.nameserver.createRecord(updateDict)
        except Exception as e:
            self.__rv = e[1]
        return self.__rv

    def delete(self, deleteDict, preserveDict = []):
        deleteRv = self.qry(deleteDict)
        print(deleteRv)
        deleteIds = set(flatten(extractIds(deleteRv)))
        preserveRv = self.qry(preserveDict)
        preserveIds = set(flatten(extractIds(preserveRv)))
        deleteOnlyIds = deleteIds - preserveIds
        self.__rv = [self.__conn.nameserver.deleteRecord({'id': e}) for e in deleteOnlyIds]
        return self.__rv

    def addList(self, baseRecord, contentList):
        self.add(makeDictList(baseRecord, 'content', contentList))

    def delList(self, baseRecord, contentDelete = '*', contentPreserve = []):
        if type(contentDelete) is str:
            contentDelete = [contentDelete]
        if '*' in contentDelete:
            delList = baseRecord
        else:
            delList = makeDictList(baseRecord, 'content', contentDelete)
        presList = makeDictList(baseRecord, 'content', contentPreserve)
        print(delList)
        print(presList)
        self.delete(delList, presList)

    def setList(self, baseRecord, contentList):
        self.addList(baseRecord, contentList)
        self.delList(baseRecord, '*', contentList)




