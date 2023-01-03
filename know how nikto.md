# know how nikto

[Download](https://github.com/sullo/nikto)

Nikto is a web server assessment tool, designed to identify and analyze various default and insecure files, configurations, and programs on just about any type of web server.


```bash
## know how oscp tool
```

```bash
## Scan a host 
Nikto –h (Hostname/IP address)

## Scan host targeting specific ports 
Nikto -h -port (Port Number1),(Port Number2)

## Define maximum scan time
Nikto -h (Hostname) -maxtime (seconds) 

## Scan duration 

Nikto -h-until

## Define host header 

Nikto -h-vhost

## Skip http 404 guessing 

Nikto -h-no404

## Stop using SSL during scan

Nikto -h-nossl

##Force to use SSL

Nikto -h-ssl

## Update scan engine plugins

Nikto -update

##Check database 

Nikto -h-dbcheck

##Input output to a file 

Nikto -h (Hostname/IP address) -output (filename)

## Web host scan via a proxy

Nikto -h-useproxy (Proxy IP address)

## Use a specified file as a database 

Nikto -h-config (filename.conf)

##Stop DNS lookup for hosts

Nikto -h-nolookup

## Stop caching responses for scans

Nikto -h-nocache
```
