#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

import unittest
from dnsuptools import dnsupdate
from tests.passwords import inwxUserDict, inwxPasswdDict

testdomain = "test23.bahn.cf"

class TestDNSUpdate(unittest.TestCase):
    def setUp(self):
        self.dnsUpdate = dnsupdate.DNSUpdate()
        self.dnsUpdate.setHandler('inwx')
        self.dnsUpdate.handler.setUserDict(inwxUserDict)
        self.dnsUpdate.handler.setPasswdDict(inwxPasswdDict)

    def testDNSops(self):

        self.dnsUpdate.delete({'name': testdomain})
        qry = self.dnsUpdate.qry({'name': testdomain})
        with self.subTest("Query result length after first delete 0"):
            self.assertEqual(len(qry), 0)
        self.dnsUpdate.add({'name': testdomain, 'type': 'A', 'content': '1.2.3.4'})
        qry = self.dnsUpdate.qry({'name': testdomain})
        with self.subTest("Query result length after add 1"):
            self.assertEqual(len(qry), 1)
        self.dnsUpdate.add([{'name': testdomain, 'type': 'NS', 'content': 'ns23.'+testdomain}, {'name': testdomain, 'type': 'MX', 'content': 'mx23.'+testdomain}])
        qry = self.dnsUpdate.qry({'name': testdomain})
        with self.subTest("Query result length after 2 additional adds 3"):
            self.assertEqual(len(qry), 3)
        self.dnsUpdate.delete([{'name': testdomain, 'type': 'NS'}])
        qry = self.dnsUpdate.qry({'name': testdomain})
        with self.subTest("Query result length after 1 delete 2"):
            self.assertEqual(len(qry), 2)
        self.dnsUpdate.delete({'name': testdomain})
        qry = self.dnsUpdate.qry({'name': testdomain})
        with self.subTest("Query result length after last delete 0"):
            self.assertEqual(len(qry), 0)



    def tearDown(self):
        self.dnsUpdate.handler.disconnect()

