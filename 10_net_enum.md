# Net enum


## Discover Hosts
### netdiscover
    # netdiscover -r 192.168.206.0/24


### nbtscan
    Scan for Netbios Hosts
    Url: http://www.inetcat.org/software/nbtscan.html
    # nbtscan 192.168.206.0/24





## Port scanner
### Nmap

```
# nmap -sV -A -p- 192.168.206.23
```
```
# nmap -sV -sC -oN nmap.log 10.10.10.93
```

    -sV : Attempts to determine the version of the service running on port
    -sC : Scan with default NSE scripts. Considered useful for discovery and safe
    -A   : Enables OS detection, version detection, script scanning, and traceroute
    -p-  : Port scan all ports
    -oN nmap.log : output normal file
          

### Unicornscan 
    unicorn

### One Two Punch
    use unicorn to scan open ports, then nmap to identify services
    Url: https://github.com/superkojiman/onetwopunch
