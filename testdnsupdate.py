#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from dnsupdate import *
from .passwords import *
import sys


update = DNSUpdate()

#update.setUserDict(inwxUserDict)
#update.setPasswdDict(inwxPasswdDict)
#update.setUser('entroserv')
#update.setPasswd(sys.argv[1])

#update.qry({'domain': 'entroserv.de'})
print(update.qry({'name': 'entroserv.de'}))
print(update.qry({'name': 'smartrns.net'}))

print(update.qry([{'name': 'entroserv.de'}, {'name': 'smartrns.net'}]))

print(update.add({'name': 'test42.entroserv.de', 'type': 'A', 'content': '1.2.3.4'}))
print(update.add({'name': 'test42.entroserv.de', 'type': 'A', 'content': '1.2.3.5'}))
#print(update.delete({'name': 'test42.entroserv.de', 'type': 'A', 'content': '1.2.3.4'}))


update.add([{'name': 'entroserv.de', 'type': 'TXT', 'content': 'hello'}, {'name': 'entroserv.de', 'type': 'TXT', 'content': 'this'}, {'name': 'entroserv.de', 'type': 'TXT', 'content': 'is'}, {'name': 'entroserv.de', 'type': 'TXT', 'content': 'a'}, {'name': 'entroserv.de', 'type': 'TXT', 'content': 'test'}])


update.delete([{'name': 'entroserv.de', 'type': 'TXT', 'content': 'hello'}, {'name': 'entroserv.de', 'type': 'TXT', 'content': 'this'}, {'name': 'entroserv.de', 'type': 'TXT', 'content': 'is'}, {'name': 'entroserv.de', 'type': 'TXT', 'content': 'a'}, {'name': 'entroserv.de', 'type': 'TXT', 'content': 'test'}], {'name': 'entroserv.de', 'type': 'TXT', 'content': 'a'})

