#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

import unittest
from dnsuptools import dnsupdate
from tests.passwords import inwxUserDict, inwxPasswdDict

#turl = "test23.bahn.cf"
turl = "test42.bahn.cf"
#turl = "bahn.cf"

def filterResult(x, pkeys, skeys):
    if type(pkeys) is not list:
        pkeys = [pkeys]
    if type(skeys) is not list:
        skeys = [skeys]
    return {'_'.join([str(e[pkey]) for pkey in pkeys]): \
            {k: v for k, v in e.items() if k in skeys} for e in x}

class TestDNSUpdateMiscFncs(unittest.TestCase):
    def testFlatten(self):
        x = [1,2,3,[4,5,[6],7],8]
        y = dnsupdate.flatten(x)
        self.assertEqual(y, [1,2,3,4,5,6,7,8])

    def testExtractIDs(self):
        x = [{'id':1,'xy':'a'},{'id':2},[{'id':3},{'id':4},[{'id':5}],{'id':6}]]
        y = dnsupdate.extractIds(x)
        self.assertEqual(y, [1,2,[3,4,[5],6]])

    def testDefaultDictList(self):
        baseDict = {'x':1,'y':2}
        dictList = [{},{'z':3},{'x':3},{'x':3,'y':4},{'x':5,'y':6,'z':7}]
        y = dnsupdate.defaultDictList(baseDict, dictList)
        self.assertEqual(y, [{'x':1,'y':2},{'x':1,'y':2,'z':3},{'x':3,'y':2},
                             {'x':3,'y':4},{'x':5,'y':6,'z':7}])


    def testMatchUpperLabels(self):
        mul = dnsupdate.MatchUpperLabels()
        fltr = {'name': 'sub.domain.local', 'domain': 'domain.local'}
        x = [{'name': 'sub.domain.local'}, {'name': 'domain.local'},
             {'name': 'very.sub.domain.local'}]
        mul.pre(fltr)
        mul.post(x)
        with self.subTest("MatchUpperLabels.pre(filterDict)"):
            self.assertEqual(fltr, {'domain': 'domain.local'})
        with self.subTest("MatchUpperLabels.stateDict"):
            self.assertEqual(mul.stateDict, {'name': 'sub.domain.local'})
        with self.subTest("MatchUpperLabels.post(rv)"):
            self.assertEqual(x, [{'name': 'sub.domain.local'},
                                 {'name': 'very.sub.domain.local'}])




class TestDNSUpdate(unittest.TestCase):
    def setUp(self):
        self.dnsu = dnsupdate.DNSUpdate()
        self.dnsu.setHandler('inwx')
        self.dnsu.handler.setUserDict(inwxUserDict)
        self.dnsu.handler.setPasswdDict(inwxPasswdDict)
        self.dnsu.delete({'name': turl}, wild=True)

    def testDNSops(self):
        self.dnsu.delete({'name': turl}, wild=True)
        qry = self.dnsu.qry({'name': turl})
        with self.subTest("Query result length after first delete 0"):
            self.assertEqual(len(qry), 0)
        self.dnsu.add({'name': turl, 'type': 'A', 'content': '1.2.3.4'})
        qry = self.dnsu.qry({'name': turl})
        with self.subTest("Query result length after add 1"):
            self.assertEqual(len(qry), 1)
        self.dnsu.add([{'name': turl, 'type': 'NS', 'content': 'ns23.'+turl},
                       {'name': turl, 'type': 'MX', 'content': 'mx23.'+turl}])
        qry = self.dnsu.qry({'name': turl})
        with self.subTest("Query result length after 2 additional adds 3"):
            self.assertEqual(len(qry), 3)
        self.dnsu.delete([{'name': turl, 'type': 'NS'}])
        qry = self.dnsu.qry({'name': turl})
        with self.subTest("Query result length after 1 delete 2"):
            self.assertEqual(len(qry), 2)
        self.dnsu.delete({'name': turl})
        qry = self.dnsu.qry({'name': turl})
        with self.subTest("Query result length after last delete 0"):
            self.assertEqual(len(qry), 0)

    def testUpdateOps(self):
        self.dnsu.delete({'name': turl}, wild=True)
        y = [{'prio': 20, 'content': 'mx20.xmpl'},
             {'prio': 30, 'content': 'mx30.xmpl'},
             {'prio': 40, 'content': 'mx40.xmpl'}]
        self.dnsu.addDictList({'name': turl, 'type': 'MX'}, y)
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        print(q)
        refq = filterResult(q, ['content'], ['name', 'type', 'id', 'prio'])
        ref = {k: v for k, v in refq.items() if k != 'mx20.xmpl'}
        ref['mxup.xmpl'] = refq['mx20.xmpl']
        self.dnsu.update({'name': turl, 'type': 'MX', 'prio': 20},
                         {'content': 'mxup.xmpl'})
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        print(q)
        res = filterResult(q, ['content'], ['name', 'type', 'id', 'prio'])
        with self.subTest("Check update() - id and content"):
            self.assertEqual(res, ref)
        ref = {k: v for k, v in refq.items() if not (k == 'mx30.xmpl' or k ==
                                                     'mx20.xmpl')}
        ref['mxup30.xmpl'] = refq['mx30.xmpl']
        ref['mxup.xmpl'] = refq['mx20.xmpl']
        self.dnsu.update({'name': turl, 'type': 'MX', 'content': 'mx30.xmpl'},
                         {'content': 'mxup30.xmpl'})
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        print(q)
        res = filterResult(q, ['content'], ['name', 'type', 'id', 'prio'])
        with self.subTest("Check update() - preserve prio in updated record"):
            self.assertEqual(res, ref)


    def testListOps(self):
        self.dnsu.delList({'name': turl, 'type': 'MX'})
        x = [{'name': turl, 'type': 'MX', 'prio': 10, 'content': 'mx23.xmpl'},
             {'name': turl, 'type': 'MX', 'prio': 10, 'content': 'mx42.xmpl'}]
        y = [{'prio': 20, 'content': 'mx20.xmpl'},
             {'prio': 30, 'content': 'mx30.xmpl'},
             {'prio': 40, 'content': 'mx40.xmpl'}]
        contx = [e['content'] for e in x]
        self.dnsu.addList({'name': turl, 'type': 'MX', 'prio': 10}, contx)
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        res = filterResult(q, ['name', 'content'], ['type', 'content', 'prio'])
        ref = filterResult(x, ['name', 'content'], ['type', 'content', 'prio'])
        with self.subTest("Check addList()"):
            self.assertEqual(res, ref)
        self.dnsu.addDictList({'name': turl, 'type': 'MX'}, y)
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        res = filterResult(q, ['content'], ['content', 'prio'])
        ref = filterResult(x+y, ['content'], ['content', 'prio'])
        with self.subTest("Check addDictList()"):
            self.assertEqual(res, ref)
        self.dnsu.delList({'name': turl}, ['mx30.xmpl', 'mx40.xmpl'])
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        res = filterResult(q, ['content'], ['content', 'prio'])
        ref = filterResult(x+[y[0]], ['content'], ['content', 'prio'])
        with self.subTest("Check delList() (wo preserve)"):
            self.assertEqual(res, ref)
        self.dnsu.delList({'name': turl}, '*', ['mx20.xmpl', 'mx42.xmpl'])
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        idPresPre = [e['id'] for e in q if e['content'] == 'mx42.xmpl']
        res = filterResult(q, ['content'], ['content', 'prio'])
        ref = filterResult([x[1],y[0]], ['content'], ['content', 'prio'])
        with self.subTest("Check delList() (with preserve)"):
            self.assertEqual(res, ref)
        self.dnsu.setList({'name': turl, 'type': 'MX', 'prio': 10}, contx)
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        idPresPost = [e['id'] for e in q if e['content'] == 'mx42.xmpl']
        res = filterResult(q, ['content'], ['content', 'prio'])
        ref = filterResult(x+[y[0]], ['content'], ['content', 'prio'])
        with self.subTest("Check setList() (preserve)"):
            self.assertEqual(res, ref)
        with self.subTest("Check setList() (id preserved)"):
            self.assertEqual(idPresPost, idPresPre)
        self.dnsu.setList({'name': turl, 'type': 'MX', 'prio': 10}, [contx[1]])
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        idPresPre3 = [e['id'] for e in q if e['content'] == 'mx20.xmpl']
        idPresPost2 = [e['id'] for e in q if e['content'] == 'mx42.xmpl']
        res = filterResult(q, ['content'], ['content', 'prio'])
        ref = filterResult([x[1],y[0]], ['content'], ['content', 'prio'])
        with self.subTest("Check setList() (delete)"):
            self.assertEqual(res, ref)
        with self.subTest("Check setList() (id preserved after delete)"):
            self.assertEqual(idPresPost2, idPresPost)
        self.dnsu.setDictList({'name': turl, 'type': 'MX'}, [{}], y)
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        idPresPost3 = [e['id'] for e in q if e['content'] == 'mx20.xmpl']
        res = filterResult(q, ['content'], ['content', 'prio'])
        ref = filterResult(y, ['content'], ['content', 'prio'])
        with self.subTest("Check setDictList() (delete and preserve)"):
            self.assertEqual(res, ref)
        with self.subTest("Check setDictList() (id preserved after delete)"):
            self.assertEqual(idPresPre3, idPresPost3)
        self.dnsu.setDictList({'name': turl}, [{'prio': 30}, {'prio': 40}], x)
        q = self.dnsu.qry({'name': turl, 'type': 'MX'})
        idPresPost4 = [e['id'] for e in q if e['content'] == 'mx20.xmpl']
        res = filterResult(q, ['content'], ['content', 'prio'])
        ref = filterResult(x+[y[0]], ['content'], ['content', 'prio'])
        with self.subTest("Check setDictList() (selective delete and set)"):
            self.assertEqual(res, ref)
        with self.subTest("Check setDictList() (id preserved after set)"):
            self.assertEqual(idPresPost3, idPresPost4)



    def testWildcards(self):
        self.dnsu.delete({'name': turl}, [], True)
        recsAdded = [{'name':'text.ns42.'+turl,'type':'TXT','content':'x'},
                     {'name':'ns42.'+turl,'type':'NS','content':'ns23.xmpl'},
                     {'name':'mx42.'+turl,'type':'MX','content':'mx23.xmpl'},
                     {'name':turl,'type':'A','content':'1.2.3.4'}]
        recsDeled = [{'name': turl,'type': 'NS'},
                     {'name': turl, 'content': 'mx23.xmpl'},
                     {'name': turl, 'content': '1.2.3.4', 'type': 'TXT'}]
        recsRem = recsAdded[1:3]
        recUpd = {'name': 'mx42.'+turl, 'type': 'MX', 'content': 'mx1337.xmpl'}
        recsNew = [recsAdded[1], recUpd]
        self.dnsu.add(recsAdded)
        qry = self.dnsu.qryWild({'name': turl})
        names = {e['name'] for e in qry}
        with self.subTest("Check if all names are there"):
            self.assertEqual(names, {'text.ns42.'+turl,'ns42.'+turl,
                                     'mx42.'+turl,turl})
        recsAddedDict = filterResult(recsAdded, 'name', ['type', 'content'])
        recsQrydDict = filterResult(qry, 'name', ['type', 'content'])
        with self.subTest("Check if name, type and content are correct"):
            self.assertEqual(recsQrydDict, recsAddedDict)
        self.dnsu.delete({'name': turl}, recsDeled, True)
        qry = self.dnsu.qryWild({'name': turl})
        recsQrydDict = filterResult(qry, 'name', ['type', 'content'])
        recsRemDict = filterResult(recsRem, 'name', ['type', 'content'])
        with self.subTest("Are name, type, content correct, after preserve?"):
            self.assertEqual(recsQrydDict, recsRemDict)
        self.dnsu.update({'name': 'mx42.'+turl}, recUpd)
        qry = self.dnsu.qryWild({'name': turl})
        recsQrydDict = filterResult(qry, 'name', ['type', 'content'])
        recsNewDict = filterResult(recsNew, 'name', ['type', 'content'])
        with self.subTest("Are name, typ, content correct, after update?"):
            self.assertEqual(recsQrydDict, recsNewDict)




    def tearDown(self):
        self.dnsu.handler.disconnect()

