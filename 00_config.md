# Configuration de Kali



## Virtualbox

Télécharger la dernière version de Virtualbox : https://www.virtualbox.org/


## Kali

Télécharger l'image de Kali : https://www.kali.org/downloads/
Idéalement une image Large 64 bits : https://cdimage.kali.org/kali-2019.3/kali-linux-large-2019.3-amd64.iso

Installer Kali sous Virtualbox
- Mettre 60G de disque
- 4G de Ram
- Idéalement plusieurs processeur

Pour travailler avec des VM sur le réseau local : mettre l'interface réseau en Bridge.
Pour se connecter à un site distant avec openvpn, ou travailler en local, on peut rester en NAT.


## Mise à jour du système et installation des addons Virtualbox

    apt-get update
    apt-get upgrade -y
    apt-get install -y virtualbox-guest-x11


## Set date

    date -s "23 SEP 2019 21:45:00"


## Activer le cache pour metasploit

Il faut activer PostgreSQL et construire le cache.

$ systemctl start postgresql
$ msfdb init



## Creation du compte Zen

    $ adduser zen
    $ cat .bashrc
    xhost +SI:localuser:zen
    export DISPLAY=:0
    Ou export DISPLAY=:1


Pour ajouter des droits sudo

    $ sudo vi /etc/sudoers
    zen ALL=(ALL) NOPASSWD:ALL



## Chrome

Télécharger Chrome : https://www.google.com/chrome/

    $ apt install /root/Téléchargements/google-chrome-stable_current_amd64.deb

Ajouter des raccourcis vers :

- https://www.exploit-db.com/

- https://crackstation.net



## Visual code

````
$ mkdir  ~/.code
$ cat go_code
code --user-data-dir ~/.code .
````

## Config git

````
$ git config --global user.name "jossets"
$ git config --global user.email 13644560+jossets@users.noreply.github.com                                                                  
````



## Gobuster

Télécharger la dernière release de Gobuster : https://github.com/OJ/gobuster/releases/

    # wget https://github.com/OJ/gobuster/releases/download/v3.0.1/gobuster-linux-amd64.7z
    # 7z x gobuster-linux-amd64.7z 
    # mv gobuster-linux-amd64 /opt/gobuster

## SecLists

Télécharger la dernière version des listes de login/mots de passe/.. pour brute forcer en sérénité.
Nous rangeons ces listes avec les autres listes dans /usr/share/wordlists/

    wget https://github.com/danielmiessler/SecLists/archive/master.zip
    unzip master.zip 
    mv SecLists-master/ /usr/share/wordlists/seclists


## Libreoffice

    apt-get install libreoffice




================== Info utiles

### Avoir plusieurs onglets de shell

    Terminal [Fichier]/[Nouvel onglet]


### Screenshot

Les fichiers en .png sont enregistrés dans ~/Images

    Shift+ImpEcran
    



### Copier/coller

En cas de soucis de copier/coller entre windows et Kali

    # VBoxClient --clipboard

Si c'est trop fréquent, automatiser avec 

    echo "VBoxClient --clipboard" >> ~/.bashrc
