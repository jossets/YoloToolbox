# My Toolbox for CTF

## /etc/hosts

Certain services web utilisent un fqdn pour faire le routage. On remplace l'adresse IP par target.local

    cat /etc/hosts
    10.10.10.8  <tab> target.local

## Network enum

Un petit scan rapide pour identifier les ports ouverts, et anticiper le lancement de scan web

    nmap IPTARGET

Nous recupèrons les versions par l'examen des bannières pour chercher des exploits

    nmap -A IPTARGET

Un scan sur les 65535 ports TCP va prendre du temps, on le lance dans une autre fenetre

    nmap -sC -sV -p- IPTARGET

On lance un scan sur les ports UDP usuels, et on tente notre chance en snmp

    nmap -sU IPTARGET
    snmpwalk -c public IPTARGET


Les services sont le plus souvent HTTP, HTTPS (80,8080, 443), parfois un proxu HTTP. Souvent, on récupère ftp (21), ou NetBios/SMB. 

Le port bind(53) implique souvent des noms de machine : web.server.local, proxy.server.local à la place d'adresses IP.

## HTTP

### Burp

Nous utilisons deux navigateurs: Firefox avec Burp pour naviguer sur notre cible, et Google-chrome pour aller sur Internet.
Ainsi le proxy Burp n'est pas pollué par nos navigations.



### Source code

    Regarder le code HTML dans le navigateur
    Regarder les header HTTPs dans Burp

### Robot.txt

    /robots.txt

### Screenshot

Prendre une capture d'écran. Les fichiers en .png sont enregistrés dans ~/Images

    Shift+ImpEcran


Capturer une page web

    wkhtmltoimage http://target/path screnn.png 


### Dictionnaires web

- /usr/share/wordlists/dirb/common.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
- /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

- /usr/share/wordlists/dirb/vulns
    - is.txt
    - tomcat.txt

### Dirb

On utilise dirb pour un scan rapide avec un petit dictionnaire

    dirb http://SERVER


### Gobuster

On lance un scan plus riche avec gobuster basé sur un dictionnaire plus volumineux

    /opt/gobuster/gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://172.16.27.142  -l -x html,php,js,txt

    HTTPS: -k : skipp ssl verification

### Nikto

Nikto donne des informations sur les middlewares

    nikto -h IPSERVER -p PORTSERVER


