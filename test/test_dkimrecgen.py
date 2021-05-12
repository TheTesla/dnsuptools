#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

import unittest

from dnsuptools import dkimrecgen

class TestDKIMrecgen(unittest.TestCase):
    def testDKIMFromFile(self):
        dkim = dkimrecgen.dkimFromFile({'filename': 'test/testdkimkey2048.txt'})
        self.assertEqual(dkim, {'filename': 'test/testdkimkey2048.txt', 'p': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAucgtUOS7wajLj5aVk+J/pNjAkx/9qt4s4tuhXRsHcYcroVRHegtDTNUIZdP3oF/QERuBQAE2gfNoV2ZqC9Nop3EXf0fjOFJoUxTyOK2IXMglbOD5+sptNaJwY7OsS+jhjNJBG5Jej7HcR/eqya7kUovVCGqjy6Ii2Tik5Sun0yHz3yqKrQgdq/I3ev7xAfeiBdmL8ZweaVG8aqK51Fbf0j1VPo65F/CcXVVs00urQdkR8hjCKk3l7NMwHI6fmiOViAxMNvpv48A93K9jL3LylPErybww4XBsEMwAODuymrFvXS8e7eM8mPejZP+Me+ngPrASoUal3NCziWKmfpmqKwIDAQAB', 'keyname': 'testdkimkey', 'v': 'DKIM1', 'k': 'rsa'})



