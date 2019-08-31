
# Privilege escalation


## Get System info
```
> systeminfo | findstr /B /C:"Name" /C:"Version"
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600

> ver
Microsoft Windows [version 10.0.18362.295]

> wmic os get Caption, CSDVersion /value
Caption=Microsoft Windows 10 Professionnel
CSDVersion=
````

````

type c:\windows\system32\license.rtf 
c:\windows\system32\licenses\*
c:\windows\system32\eula.txt
````

more => http://www.fuzzysecurity.com/tutorials/16.html


````

Name	                            Version	    Build	Release Date	RTM Date
Windows 95	                        4.00	    950	    1995-08-24	
Windows 95 OEM Service Release 1	4.00	    950 A	1996-02-14	
Windows 95 OEM Service Release 2	4.00	    950 B	1996-08-24	
Windows 95 OEM Service Release 2.1	4.00	    950 B	1997-08-27	
Windows 95 OEM Service Release 2.5	4.00	    950 C	1997-11-26	
Windows 98	                        4.10	1998	1998-05-15	
Windows 98 Second Edition (SE)	    4.10	2222	1999-05-05	
Windows Me	                        4.90	3000	2000-09-14	2000-06-19
Windows NT                          3.1	                 3.10	511	1993-07-27	
Windows NT 3.1, Service Pack 3	 3.10	528	1994-11	
Windows NT 3.5	3.50	807	1994-09-21	
Windows NT 3.51	3.51	1057	1995-05-30	
Windows NT 4.0	4.0	1381	1996-08-24	1996-07-31
Windows 2000	5.0	2195	2000-02-17	1999-12-15
Windows XP	5.1	2600	2001-10-25	2001-08-24
Windows XP, Service Pack 1	5.1	2600.1105-1106	2002-09-09	
Windows XP, Service Pack 2	5.1	2600.2180	2004-08-25	
Windows XP, Service Pack 3	5.1	2600	2008-04-21	
Windows Server 2003	5.2	3790	2003-04-24	
Windows Server 2003, Service Pack 1	5.2	3790.1180	2005-03-30	
Windows Server 2003, Service Pack 2	5.2	3790	2007-03-13	
Windows Server 2003 R2	5.2	3790	2005-12-06	2005-12-06
Windows Home Server	5.2	4500	2007-11-04	2007-07-16
Windows Vista	6.0	6000	2007-01-30	2006-11-08
Windows Vista, Service Pack 1	6.0	6001	2008-02-04	
Windows Vista, Service Pack 2	6.0	6002	2009-05-26	2009-04-28
Windows Server 2008	6.0	6001	2008-02-27	2008-02-04
Windows Server 2008, Service Pack 2	6.0	6002	2009-05-26	
Windows Server 2008, Service Pack 2, Rollup KB4489887	6.0	6003	2019-03-19	
Windows 7	6.1	7600	2009-10-22	2009-07-22
Windows 7, Service Pack 1	6.1	7601	2011-02-22	
Windows Server 2008 R2	6.1	7600	2009-10-22	2009-07-22
Windows Server 2008 R2, Service Pack 1	6.1	7601	2011-02-22	2011-02-09
Windows Home Server 2011	6.1	8400	2011-04-06	2011-04-06
Windows Server 2012	6.2	9200	2012-09-04	2012-08-01
Windows 8	6.2	9200	2012-10-26	2012-08-01
Windows 8.1	6.3	9600	2013-08-27	2013-10-17
Windows Server 2012 R2	6.3	9600	2013-10-18	2013-08-27
Windows 10, Version 1507	10.0	10240	2015-07-29	2015-07-15
Windows 10, Version 1511	10.0	10586	2015-11-10	
Windows 10, Version 1607	10.0	14393	2016-08-02	
Windows 10, Version 1703	10.0	15063	2017-04-05	
Windows 10, Version 1709	10.0	16299	2017-10-17	
Windows 10, Version 1803	10.0	17134	2018-04-30	
Windows 10, Version 1809	10.0	17763	2018-10-02	
Windows 10, Version 1903	10.0	18362	2019-05-21	
Windows Server 2016, Version 1607	10.0	14393	2016-08-02	
Windows Server 2016, Version 1709	10.0	16299	2017-10-17	
Windows Server 2019, Version 1809	10.0	17763	2018-10-02	

````


## Get User info
```
hostname
echo %username%
whoami
echo %username%
net user
net user (username)
echo %userprofile%
net localgroup
net config Workstation | find "User name"
query user
wmic useraccount get name
wmic /node: "127.0.0.1" computersystem get username
qwinsta
cmdkey /list
```


## Check installed programs, permissions, and hidden files:
````
dir /q
dir /r
attrib -h *.*
wmic /node: "127.0.0.1" product get name, version
wmic product get /format:list
````
 