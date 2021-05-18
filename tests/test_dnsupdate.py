#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

import unittest
from dnsuptools import dnsupdate
from tests.passwords import inwxUserDict, inwxPasswdDict

testdomain = "test23.bahn.cf"
#testdomain = "bahn.cf"


class TestDNSUpdateMiscFncs(unittest.TestCase):
    def testFlatten(self):
        x = [1,2,3,[4,5,[6],7],8]
        y = dnsupdate.flatten(x)
        self.assertEqual(y, [1,2,3,4,5,6,7,8])

    def testExtractIDs(self):
        x = [{'id': 1, 'test': 'a'},{'id': 2},[{'id': 3}, {'id': 4},[{'id': 5}],{'id': 6}]]
        y = dnsupdate.extractIds(x)
        self.assertEqual(y, [1,2,[3,4,[5],6]])

    def testDefaultDictList(self):
        baseDict = {'x': 1, 'y': 2}
        dictList = [{}, {'z': 3}, {'x': 3}, {'x': 3, 'y': 4}, {'x': 5, 'y': 6, 'z': 7}]
        y = dnsupdate.defaultDictList(baseDict, dictList)
        self.assertEqual(y, [{'x': 1, 'y': 2}, {'x': 1, 'y': 2, 'z': 3}, {'x': 3, 'y': 2}, {'x': 3, 'y': 4}, {'x': 5, 'y': 6, 'z': 7}])


    def testMatchUpperLabels(self):
        mul = dnsupdate.MatchUpperLabels()
        fltr = {'name': 'sub.domain.local', 'domain': 'domain.local'}
        x = [{'name': 'sub.domain.local'}, {'name': 'domain.local'}, {'name': 'very.sub.domain.local'}]
        mul.pre(fltr)
        mul.post(x)
        with self.subTest("MatchUpperLabels.pre(filterDict)"):
            self.assertEqual(fltr, {'domain': 'domain.local'})
        with self.subTest("MatchUpperLabels.stateDict"):
            self.assertEqual(mul.stateDict, {'name': 'sub.domain.local'})
        with self.subTest("MatchUpperLabels.post(rv)"):
            self.assertEqual(x, [{'name': 'sub.domain.local'}, {'name': 'very.sub.domain.local'}]
)



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

    def testWildcards(self):
        self.dnsUpdate.delete({'name': testdomain}, [], True)
        recsAdded = [{'name': 'text.ns42.'+testdomain, 'type': 'TXT', 'content': 'x'}, \
                     {'name': 'ns42.'+testdomain, 'type': 'NS', 'content': 'ns23.xmpl'}, \
                     {'name': 'mx42.'+testdomain, 'type': 'MX', 'content': 'mx23.xmpl'}, \
                     {'name': testdomain, 'type': 'A', 'content': '1.2.3.4'}]
        self.dnsUpdate.add(recsAdded)
        qry = self.dnsUpdate.qryWild({'name': testdomain})
        names = {e['name'] for e in qry}
        with self.subTest("Check if all names are there"):
            self.assertEqual(names, {'text.ns42.'+testdomain, 'ns42.'+testdomain, 'mx42.'+testdomain, testdomain})
        recsAddedDict = {e['name']: {k: v for k, v in e.items() if k in ['type', 'content']} for e in recsAdded}
        recsQrydDict = {e['name']: {k: v for k, v in e.items() if k in ['type', 'content']} for e in qry}
        with self.subTest("Check if name, type and content are correct"):
            self.assertEqual(recsQrydDict, recsAddedDict)




    def tearDown(self):
        self.dnsUpdate.handler.disconnect()

