#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

def dkimFromFile(dkimDict):
    if type(dkimDict) is list:
        rv = [dkimFromFile(e) for e in dkimDict]
        dkimDict[:] = rv
        return rv
    if 'filename' not in dkimDict:
        return dkimDict
    dkimFilename = dkimDict['filename']
    with open(dkimFilename, 'r') as f:
        dkimCont = f.read()
    for r in ['"', '\n', '\r', '\t', '(', ')', ' ']:
        dkimCont = dkimCont.replace(r, '')
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



