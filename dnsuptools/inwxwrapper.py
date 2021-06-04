#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

import time
from INWX.Domrobot import ApiClient

from simpleloggerplus import simpleloggerplus as log
from dnsuptools.dnshelpers import createKeyDomainIfNotExists

inwxUserDict = {'default': 'user'}
inwxPasswdDict = {'default': 'passwd'}

class INWXwrapper:
    '''Class allows updating inwx zone entries'''
    def __init__(self):
        global inwxUserDict
        global inwxPasswdDict
        self.__apiUrl = ApiClient.API_LIVE_URL
        self.__conn = None
        self.__userDict = {'default': 'user'}
        self.__passwdDict = {'default': 'passwd'}
        self.__rv = None
        self.__openedDomain = ''
        self.__isConnected = False
        self.__loggedInCredentials = {}
        self.setUserDict(inwxUserDict)
        self.setPasswdDict(inwxPasswdDict)

    def setApiUrl(self, apiUrl):
        self.disconnect()
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
        return getDictLike(self.__passwdDict, domain, self.__passwdDict['default'])

    def getUser(self, domain):
        domain = str(domain)
        return getDictLike(self.__userDict, domain, self.__userDict['default'])

    def connect(self):
        if self.__isConnected is True:
            return
        self.__conn = ApiClient(api_url=self.__apiUrl, debug_mode=False)
        self.__isConnected = True

    def disconnect(self):
        if self.__isConnected is False:
            return
        self.logout()
        self.__conn = None
        self.__isConnected = False

    def login(self, domain):
        if 'user' in self.__loggedInCredentials and 'pass' in self.__loggedInCredentials:
            if self.getUser(domain) == self.__loggedInCredentials['user'] and self.getPasswd(domain) == self.__loggedInCredentials['pass']:
                return
        self.connect()
        loggedInCredentials = {'lang': 'en', 'user': self.getUser(domain), 'pass': self.getPasswd(domain)}
        log.debug(loggedInCredentials)
        self.__rv = self.__conn.login(loggedInCredentials['user'], loggedInCredentials['pass'])
        log.debug(self.__rv)
        if 1000 != self.__rv['code']:
            return
        self.__loggedInCredentials = dict(loggedInCredentials)
        self.__openedDomain = str(domain)
        self.__isLoggedIn = True

    def logout(self):
        if self.__isLoggedIn is False:
            return
        self.__loggedInCredentials = {}
        self.__openedDomain = ''


    def autologin(self, recordDict):
        recordDict = dict(recordDict)
        createKeyDomainIfNotExists(recordDict)
        if 'domain' in recordDict:
            self.login(recordDict['domain'])



    # Yes, login also for info needed!
    def info(self, infoDict):
        self.autologin(infoDict)
        stateDict = {}
        caaWorkaroundPre(infoDict, stateDict)
        rv = self.callAPI('nameserver.info', infoDict)
        rv = rv['resData']
        if 'record' not in rv:
            return []
        rv = rv['record']
        caaWorkaroundPost(rv, stateDict)
        return rv

    def create(self, createDict):
        createKeyDomainIfNotExists(createDict)
        self.login(createDict['domain'])
        return self.callAPI('nameserver.createRecord', createDict)

    # warning: no autologin, if no domain and no name provided
    #          - that is when you support only the record id
    #          but should not be a problem, because you can only
    #          know record id after info() needing login, automatically
    #          happen by providing domain or name
    def delete(self, deleteDict):
        self.autologin(deleteDict)
        return self.callAPI('nameserver.deleteRecord', deleteDict)

    def update(self, updateDict):
        self.autologin(updateDict)
        if 'domain' in updateDict:
            del updateDict['domain']
        return self.callAPI('nameserver.updateRecord', updateDict)

    def callAPI(self, method, params):
        for i in range(10):
            if i > 0:
                log.info('INWX api wait {} s before retry'.format(i**3))
                time.sleep(i**3)
            rv = self.__conn.call_api(api_method=method, method_params=params)
            if 2400 == rv['code']:
                log.info('INWX api error code: {}'.format(rv['code']))
                continue
            if 2500 == rv['code']:
                log.info('INWX api error code: {}'.format(rv['code']))
                continue
            if 2502 == rv['code']:
                log.info('INWX api error code: {}'.format(rv['code']))
                continue
            return rv

        log.error('INWX api retry limit exceeded!')
        log.error('INWX api error code was: {}'.format(rv['code']))
        return rv

def caaWorkaroundPre(infoDict, stateDict):
    stateDict['iscaa'] = False
    if 'type' not in infoDict:
        return
    if 'CAA' != infoDict['type']:
        return
    stateDict['iscaa'] = True
    del infoDict['type']


def caaWorkaroundPost(rv, stateDict):
    if not stateDict['iscaa']:
        return
    rv[:] = [e for e in rv if 'CAA' == e['type']]

def getDictLike(dataDict, searchFor, default=None, splitChar='.'):
    splitList = searchFor.split(splitChar)
    for i in range(len(splitList)):
        subPart = splitChar.join(splitList[i:])
        if subPart in dataDict:
            return dataDict[subPart]
    return default

