#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

import unittest

from dnsuptools import dkimrecgen

class TestDKIMrecgen(unittest.TestCase):
    def testDKIMFromFile(self):
        dkim = dkimFromFile('key50.txt')


