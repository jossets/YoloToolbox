# HTTP scanners

- https://github.com/infodox/python-pty-shells/blob/master/udp_pty_backconnect.py.


## Print password list

```
#!/usr/bin/python
filename = '/usr/share/john/password.lst'
filename = 'usr/share/dirb/wordlists/big.txt'
filename = '/usr/share/wfuzz/wordlist/general/big.txt'
filename = '/usr/share/wordlists/rockyou.txt'
filename = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
filename = '/usr/share/dirb/wordlists/common.txt'

f = open(filename, 'r')  
for line in f.readlines():  
    pw = line.strip('\n')
    print(pw)
```


## Get url 

```
#!/usr/bin/python

import requests

ip='10.10.10.21'
port='3128'
url = 'http://'+ip'+':'+port+'/'

session = requests.session()
resp = session.get(url+"/index.php")

print ("Request:")
print (resp.request.headers)
print (resp.request.body)

# Dump Response
print ("Response:")
print (resp.status_code)
print (resp.headers)
print (resp.text)
print (session.cookies)
```

## Get returned CSRF token in HTML

```
import requests
import warnings
from bs4 import BeautifulSoup

# turn off BeautifulSoup warnings
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
resp = request.get(url+"/index.php")
html_content = resp.text
soup = BeautifulSoup(html_content)
token = soup.findAll('input')[3].get("value")  # 3rd <imput  value="aeaaazzezzddfrf"> tag in html
```


## Get url with Basic Auth header

- https://2.python-requests.org/en/master/user/authentication/

```
#!/usr/bin/python

import requests

session = requests.session()
resp = session.get(url+"/index.php", auth=HTTPBasicAuth('user', 'pass'))

```


## Post url 

```
#!/usr/bin/python

import requests

ip='10.10.10.21'
port='3128'
url = 'http://'+ip'+':'+port+'/'

session = requests.session()
    
post_data = {
    "useralias": username,
    "password": password,
    "submitLogin": "Connect",
    "centreon_token": token
}
login_request = request.post(url+"/index.php", post_data)

```

## Handle redirect

```
print (resp.history)

redirect_resp = resp.history[0]

print (redirect_resp) #.status_code)

print (redirect_resp.headers)
print (redirect_resp.text)
```