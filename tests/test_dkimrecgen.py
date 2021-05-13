#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

import unittest

from dnsuptools import dkimrecgen

class TestDKIMrecgen(unittest.TestCase):
    def testDKIMFromFile1024(self):
        dkim = dkimrecgen.dkimFromFile({'filename': 'test/testdkimkey1024.txt'})
        self.assertEqual(dkim, {'filename': 'test/testdkimkey1024.txt', 'p': 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQP7L2UVYrwo6pNHEXzSGrT7B+P8HBTEX6AecR9xTHr+Y9WwiYJAaKlLESqTB5SzQYlO6c+QeOv1fhnExBRxMqQEM0FhpvdwBadYx5Df4bSxt/5fjherBAiE9FbnTWWNDO6isGdAJ75+yWceRvXx0MajqSUwggqaZWNirWJUq34QIDAQAB', 'keyname': 'testdkimkey', 'v': 'DKIM1', 'k': 'rsa'})

    def testDKIMFromFile2048(self):
        dkim = dkimrecgen.dkimFromFile({'filename': 'test/testdkimkey2048.txt'})
        self.assertEqual(dkim, {'filename': 'test/testdkimkey2048.txt', 'p': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAucgtUOS7wajLj5aVk+J/pNjAkx/9qt4s4tuhXRsHcYcroVRHegtDTNUIZdP3oF/QERuBQAE2gfNoV2ZqC9Nop3EXf0fjOFJoUxTyOK2IXMglbOD5+sptNaJwY7OsS+jhjNJBG5Jej7HcR/eqya7kUovVCGqjy6Ii2Tik5Sun0yHz3yqKrQgdq/I3ev7xAfeiBdmL8ZweaVG8aqK51Fbf0j1VPo65F/CcXVVs00urQdkR8hjCKk3l7NMwHI6fmiOViAxMNvpv48A93K9jL3LylPErybww4XBsEMwAODuymrFvXS8e7eM8mPejZP+Me+ngPrASoUal3NCziWKmfpmqKwIDAQAB', 'keyname': 'testdkimkey', 'v': 'DKIM1', 'k': 'rsa'})

    def testDKIMFromFile4096(self):
        dkim = dkimrecgen.dkimFromFile({'filename': 'test/testdkimkey4096.txt'})
        self.assertEqual(dkim, {'filename': 'test/testdkimkey4096.txt', 'p': 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxTvW1ZqXNIFEJzpU5xwLPTna84vKpeWM83MS8jf7THtYfNMJmtG706j2fHmWG55uuU0r5fnYaHOBj1IT4qtFlzHDjqzrQYNUpTzsmHqpe3EMec/Zhja5Rzd/HLCZXFzBpe7welj0fYM81StCs1GrDKQvtMkqdP2VfcWNEdXksffXPMK5T5nw4tO1q99xiIGxr4+lBo12zNaUrtv18E7klBGhYkEfA1EPL5oYGKnHaBD935YU7CM0UQP+MbunM0+Tj02EfT2zwpxRkQf9a0nRqvdzgWqEDTleyXiWVp8TKqTKhoSiLmqZPv/c3d+YDAfe2L5cIDgdGRJ0eqrAsKrebf+YmVmQgr3BRfkrXGwfbg2hyqU2VCPf40KG8NOMI/4CAHbkf1RhUzv+1u8uF32xUKrYlUt8TH2BODE4CHg7OzCBCxu0mUJSMEcsgekOALm0ArDWts/8k1Dtk2NKhoHiKCLl3Q/C8W0A4bkjNKj4IEe11UYUXEJdpq0M5JawBQ1rp7YOrRnCMN5YCvIXUwt5S+OEFgmo5hO7NtFGFBfEgdaM21c5dLlpVzaWXDyTW8FFAPCN/xFqR6xhKLTzJppnD2RIvak7hNnEfc6BkNTR1sBzx23jgwfTX2Te287zQRQeORONoARWGFn1UnCz7NeomuOTugEuDudv/sydfX380gMCAwEAAQ==', 'keyname': 'testdkimkey', 'v': 'DKIM1', 'k': 'rsa'})


