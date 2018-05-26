#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from .inwxclient.inwx import domrobot 
from .simplelogger import simplelogger as log 

inwxUserDict = {'default': 'user'}
inwxPasswdDict = {'default': 'passwd'}

def createKeyDomainIfNotExists(d):
    log.debug(d)
    if 'name' not in d.keys():
        return
    if 'domain' not in d.keys():
        d['domain'] = '.'.join(d['name'].split('.')[-2:])

class INWXwrapper:
    '''Class allows updating inwx zone entries'''
    def __init__(self):
        global inwxUserDict
        global inwxPasswdDict
        self.__apiUrl = 'https://api.domrobot.com/xmlrpc/'
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
        if domain not in self.__passwdDict.keys():
            domain = 'default'
        return self.__passwdDict[domain]

    def getUser(self, domain):
        domain = str(domain)
        if domain not in self.__userDict.keys():
            domain = 'default'
        return self.__userDict[domain]

    def connect(self):
        if self.__isConnected is True:
            return
        self.__conn = domrobot(self.__apiUrl, False)
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
        self.__rv = self.__conn.account.login(loggedInCredentials)
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

    # Yes, login also for info needed!
    def info(self, infoDict):
        createKeyDomainIfNotExists(infoDict)
        self.login(infoDict['domain'])
        return self.__conn.nameserver.info(infoDict)

    def create(self, createDict):
        createKeyDomainIfNotExists(createDict)
        self.login(createDict['domain'])
        return self.__conn.nameserver.createRecord(createDict)

    # warning: no autologin, if no domain and no name provided
    #          - that is when you support only the record id
    #          but should not be a problem, because you can only 
    #          know record id after info() needing login, automatically 
    #          happen by providing domain or name
    def delete(self, deleteDict):
        if 'name' in deleteDict:
            createKeyDomainIfNotExists(deleteDict)
        if 'domain' in deleteDict:
            self.login(deleteDict['domain'])
        return self.__conn.nameserver.deleteRecord(deleteDict)

    def update(self, updateDict):
        print(updateDict)
        if 'name' in updateDict:
            createKeyDomainIfNotExists(updateDict)
        print(updateDict)
        if 'domain' in updateDict:
            self.login(updateDict['domain'])
            del updateDict['domain'] 
        return self.__conn.nameserver.updateRecord(updateDict)


