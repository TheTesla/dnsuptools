#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

import unittest

from dnsuptools import tlsarecgen

class TestTLSArecgen(unittest.TestCase):
    def testTLSAFromFile301(self):
        tlsa = tlsarecgen.tlsaFromFile({'filename': 'tests/fullchain.pem', 'usage': 3, 'selector': 0, 'matchingtype': 1})
        self.assertEqual(tlsa['tlsa'], b'edad412aed22e45ef40b0dc8bfae40306b0babba4e0aab0985e5208c6c512fe7')

    def testTLSAFromFile311(self):
        tlsa = tlsarecgen.tlsaFromFile({'filename': 'tests/fullchain.pem', 'usage': 3, 'selector': 1, 'matchingtype': 1})
        self.assertEqual(tlsa['tlsa'], b'db34027aae2af459f0279bebc049ef2127233b1b9fc23c2223f08cf36f0ee6a5')

    def testTLSAFromFile302(self):
        tlsa = tlsarecgen.tlsaFromFile({'filename': 'tests/fullchain.pem', 'usage': 3, 'selector': 0, 'matchingtype': 2})
        self.assertEqual(tlsa['tlsa'], b'3e4a29703c33a2ec5cc1c6b798da3bc69510bd16f7a4f3e6747dfa8aa3e029217ee6effec41aea9090bd7e8ea19156492bfe58f1adac71fcfa23d44e98aa8ad2')

    def testTLSAFromFile312(self):
        tlsa = tlsarecgen.tlsaFromFile({'filename': 'tests/fullchain.pem', 'usage': 3, 'selector': 1, 'matchingtype': 2})
        self.assertEqual(tlsa['tlsa'], b'b157743af61c14cb16f840208cc9d88a1454a76d0e9051f12a530201ca89d10c2c2c876914770299ac5e39706923153ded0c7ea7cb8c4517a0d613230fd79b66')

    def testTLSAFromFile201(self):
        tlsa = tlsarecgen.tlsaFromFile({'filename': 'tests/fullchain.pem', 'usage': 2, 'selector': 0, 'matchingtype': 1})
        self.assertEqual(tlsa['tlsa'], b'0f39373b3dab935434b5eceab8fd22249a2dcdf90a33fc5a71221d20f2d8e1b9')

    def testTLSAFromFile211(self):
        tlsa = tlsarecgen.tlsaFromFile({'filename': 'tests/fullchain.pem', 'usage': 2, 'selector': 1, 'matchingtype': 1})
        self.assertEqual(tlsa['tlsa'], b'ceb408dbfd6af22d9244f98c675b0c9ed2241be94c5b495e80f168903a379eb6')

    def testTLSAFromFile202(self):
        tlsa = tlsarecgen.tlsaFromFile({'filename': 'tests/fullchain.pem', 'usage': 2, 'selector': 0, 'matchingtype': 2})
        self.assertEqual(tlsa['tlsa'], b'6363ee8e61e476c46978e1eb388cfd7ad3a57713d89cad292176bfdb10c3628691c763ed5cbce8f904657a6427bad22ed9106ea0e25428575a5d1ef0fa20b9f5')

    def testTLSAFromFile212(self):
        tlsa = tlsarecgen.tlsaFromFile({'filename': 'tests/fullchain.pem', 'usage': 2, 'selector': 1, 'matchingtype': 2})
        self.assertEqual(tlsa['tlsa'], b'187160f11f4df298647ea2d48504ecf06f32ea255d54642174bff488670108555599424567ba1949df6713ab14947eca724fe73fa9cd14ba166863686fb17728')

