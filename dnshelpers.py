#!/usr/bin/env python
# -*- encoding: UTF8 -*-

def createKeyDomainIfNotExists(d):
    if 'name' not in d.keys():
        return
    if 'domain' not in d.keys():
        d['domain'] = '.'.join(d['name'].split('.')[-2:])

