#!/usr/bin/env python
# -*- encoding: UTF8 -*-

from subprocess import *
import re

def dkimFromFile(dkimFilename):
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
    return n, v, k, p



