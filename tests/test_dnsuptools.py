#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

import unittest
from dnsuptools import dnsuptools
from tests.passwords import inwxUserDict, inwxPasswdDict

turl = "test23.bahn.cf"

class TestDNSUptoolsMiscFncs(unittest.TestCase):
    def testParseNSentry(self):
        x = {'name': 'testname', 'content': 'testcontent', 'ttl': 3600}
        y = dnsuptools.parseNSentry(x)
        self.assertEqual(y, {'ns': 'testcontent'})


class TestDNSUptools(unittest.TestCase):
    def setUp(self):
        self.dnsu = dnsuptools.DNSUpTools()
