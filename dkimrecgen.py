#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from subprocess import *
import re

#def dkimFromFile(dkimFilename):
def dkimFromFile(dkimDict):
    if type(dkimDict) is list:
        rv = [dkimFromFile(e) for e in dkimDict]
        dkimDict[:] = rv
        return rv
    if 'filename' not in dkimDict:
        return dkimDict
    dkimFilename = dkimDict['filename']
    dkimCont = check_output(('cat', str(dkimFilename)))
    dkimCont = re.sub('[\"\n\r\t\(\)\ ]', '', dkimCont)
    n = dkimCont.split('._domainkey')[0]
    try:
        v = dkimCont.split('v=')[1]
        v = v.split(';')[0]
    except:
        v = None
    try:
        k = dkimCont.split('k=')[1]
        k = k.split(';')[0]
    except:
        k = None
    try:
        p = dkimCont.split('p=')[1]
        p = p.split(';')[0]
    except:
        p = None
    formFileDict = {'p': p, 'keyname': n, 'v': v, 'k': k}
    for k, v in formFileDict.items():
        if k in dkimDict.keys():
            continue
        dkimDict[k] = v
    return dkimDict



