#!/usr/bin/env python
# -*- encoding: UTF8 -*-


from inwx import domrobot, prettyprint, getOTP
from sys import argv


def main():
    api_url = argv[1]
    inwx_conn = domrobot(api_url, False)
    username = argv[2]
    password = argv[3]
    loginRet = inwx_conn.account.login({'lang': 'en', 'user': username, 'pass': password})
    name = argv[5]
    domain = argv[6]

    if 'tfa' in loginRet and loginRet['tfa'] == 'GOOGLE-AUTH':
        loginRet = inwx_conn.account.unlock({'tan': getOTP(shared_secret)})

    checkRet = inwx_conn.domain.check({'domain': domain})
    if 'qry' != argv[4]:
        print(str(prettyprint.domain_check(checkRet)))
    if 'add' == argv[4]:
        ttl = 3600
        prio = 0
	if 9 < len(argv):
            ttl = argv[9]
	if 10 < len(argv):
            prio = argv[10]
        updateRet = inwx_conn.nameserver.createRecord({'domain': domain, 'type': argv[7], 'name': name, 'content': argv[8], 'ttl': ttl, 'prio': prio})
        print(updateRet)
    elif 'del' == argv[4]:
        infoRet = inwx_conn.nameserver.info({'domain': domain, 'name': name})
        print(infoRet)
        for record in infoRet['resData']['record']:
            if len(argv) > 7:
                if record['type'] != argv[7]:
                    continue
            if len(argv) > 8:
		if record['content'] != argv[8]:
                    continue
            updateRet = inwx_conn.nameserver.deleteRecord({'id': record['id']})
            print(updateRet)
    elif 'qry' == argv[4]:
        if 7 < len(argv):
            infoRet = inwx_conn.nameserver.info({'domain': domain, 'name': name, 'type': argv[7]})
        else:
            infoRet = inwx_conn.nameserver.info({'domain': domain, 'name': name})

        # print(infoRet)
        if 'record' in infoRet['resData']:
            for record in infoRet['resData']['record']:
                print(record['content'])
    else:
        pass


if __name__ == '__main__':
    main()

