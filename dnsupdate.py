#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from inwxclient.inwx import domrobot, prettyprint, getOTP


def createKeyDomainIfNotExists(d):
    if 'domain' not in d.keys():
        d['domain'] = '.'.join(d['name'].split('.')[-2:])

def extractIds(rv):
    if type(rv) is list:
        return [extractIds(e) for e in rv]
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

class DNSUpdate:
    '''Class allows updating inwx zone entries'''
    def __init__(self):
        self.__apiUrl = 'https://api.domrobot.com/xmlrpc/'
        self.__conn = None
        self.__user = 'user'
        self.__passwd = 'passwd'
        self.__rv = None
        self.__isOpened = False

    def setApiUrl(self, apiUrl):
        self.__apiUrl = apiUrl

    def setUser(self, user):
        self.__user = user

    def setPasswd(self, passwd):
        self.__passwd = passwd

    def __open(self):
        if self.__isOpened is True:
            return
        self.__conn = domrobot(self.__apiUrl, False)
        self.__rv = self.__conn.account.login({'lang': 'en', 'user': self.__user, 'pass': self.__passwd})
        if 1000 != self.__rv['code']:
            return
        self.__isOpened = True

    def close(self):
        self.__isOpened = False

    def qry(self, filterDict):
        if type(filterDict) is list:
            self.__rv = [self.qry(e) for e in filterDict]
            return self.__rv
        self.__open()
        createKeyDomainIfNotExists(filterDict)
        self.__rv = self.__conn.nameserver.info(filterDict)
        return self.__rv

    def add(self, updateDict):
        if type(updateDict) is list:
            self.__rv = [self.add(e) for e in updateDict]
            return self.__rv
        self.__open()
        createKeyDomainIfNotExists(updateDict)
        try:
            self.__rv = self.__conn.nameserver.createRecord(updateDict)
        except Exception as e:
            self.__rv = e[1]
        return self.__rv

    def delete(self, deleteDict, preserveDict = []):
        deleteRv = self.qry(deleteDict)
        deleteIds = set(flatten(extractIds(deleteRv)))
        preserveRv = self.qry(preserveDict)
        preserveIds = set(flatten(extractIds(preserveRv)))
        deleteOnlyIds = deleteIds - preserveIds
        self.__rv = [self.__conn.nameserver.deleteRecord({'id': e}) for e in deleteOnlyIds]
        return self.__rv




