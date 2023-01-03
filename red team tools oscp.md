# know how red team tools

```bash
## know how tools
```
### know how tools eumeration
```bash
## know how gathering informtation
## know how recon tools
## know how tools enumeration
## know how enumeration tools
```

[AutoRecon](https://github.com/Tib3rius/AutoRecon) AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services. It is intended as a time-saving tool for use in CTFs and other penetration testing environments (e.g. OSCP). It may also be useful in real-world engagements.

```bash
## know how smb tools
## know how samba tools
```

[SMBclient](https://www.kali.org/tools/samba/)

[Enum4linux](https://www.kali.org/tools/enum4linux/) Enum4linux is a tool for enumerating information from Windows and Samba systems.

[Redis-cli](https://redis.io/docs/getting-started/)

## know how snmp

[snmp](http://www.nothink.org/codes/snmpcheck/index.php)

[onesixtyone](https://github.com/trailofbits/onesixtyone)

### know how web scanner

```bash

## web scanner
## web scanner install


know how vpn windows --> openvpn comunity

sudo apt-get install libwebkitgtk-1.0 default-jdk unzip

## errors

# Unrecognized VM option 'PermSize=128m'
# delete from vega.ini
-XX:PermSize=128m
-XX:MaxPermSize=256m
2.Next execute the follow commands:
apt-get install libwebkitgtk-1.0
apt-get install libwebkitgtk-1.0-common
apt-get install libwebkitgtk-1.0-0

```

## know how tools web ewpt ewptx oscp

```bash
## know how tools ewpt ewptx oscp
```

[httpx](https://github.com/projectdiscovery/httpx) httpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library

[nikto](https://www.kali.org/tools/nikto/)

### know how tools web scanner

[Nuclei](https://github.com/projectdiscovery/nuclei) is used to send requests across targets based on a template, leading to zero false positives and providing fast scanning on a large number of hosts. Nuclei offers scanning for a variety of protocols, including TCP, DNS, HTTP, SSL, File, Whois, Websocket, Headless etc. With powerful and flexible templating, Nuclei can be used to model all kinds of security checks. 

[Fuxploider](https://github.com/almandin/fuxploider) is an open source penetration testing tool that automates the process of detecting and exploiting file upload forms flaws. This tool is able to detect the file types allowed to be uploaded and is able to detect which technique will work best to upload web shells or any malicious file on the desired web server.

[Uniscan](https://github.com/poerschke/Uniscan)

[seclist](https://github.com/danielmiessler/SecLists.git)

[ffuf](https://github.com/ffuf/ffuf): Fast web fuzzer
```bash
## know how oscp tool
## know how gathering subdomains
ffuf -u "https://FUZZ.fullledcolor.es" -w SecLists/Discovery/Web-Content/raft-large-words.txt

## know how gathering directories
ffuf -u "https://fullledcolor.es/FUZZ" -w SecLists/Discovery/Web-Content/raft-large-words.txt

## know how gathering files php
ffuf -u "https://fullledcolor.es/FUZZ" -w SecLists/Discovery/Web-Content/raft-large-words.txt -e .php

## know how gathering files php not show 404
ffuf -u "https://fullledcolor.es/FUZZ" -w SecLists/Discovery/Web-Content/raft-large-words.txt -e .php -fc 404

# Directory discovery
ffuf -w /path/to/wordlist -u https://target/FUZZ

# Adding classical header (some WAF bypass)
ffuf -c -w "/opt/host/main.txt:FILE" -H "X-Originating-IP: 127.0.0.1, X-Forwarded-For: 127.0.0.1, X-Remote-IP: 127.0.0.1, X-Remote-Addr: 127.0.0.1, X-Client-IP: 127.0.0.1" -fs 5682,0 -u https://target/FUZZ

# match all responses but filter out those with content-size 42
ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v

# Fuzz Host-header, match HTTP 200 responses.
ffuf -w hosts.txt -u https://example.org/ -H "Host: FUZZ" -mc 200

# Virtual host discovery (without DNS records)
ffuf -w /path/to/vhost/wordlist -u https://target -H "Host: FUZZ" -fs 4242


# Playing with threads and wait
./ffuf -u https://target/FUZZ -w /home/mdayber/Documents/Tools/Wordlists/WebContent_Discovery/content_discovery_4500.txt -c -p 0.1 -t 10


# GET param fuzzing, filtering for invalid response size (or whatever)
ffuf -w /path/to/paramnames.txt -u https://target/script.php?FUZZ=test_value -fs 4242

# GET parameter fuzzing if the param is known (fuzzing values) and filtering 401
ffuf -w /path/to/values.txt -u https://target/script.php?valid_name=FUZZ -fc 401



# POST parameter fuzzing
ffuf -w /path/to/postdata.txt -X POST -d "username=admin\&password=FUZZ" -u https://target/login.php -fc 401

# Fuzz POST JSON data. Match all responses not containing text "error".
ffuf -w entries.txt -u https://example.org/ -X POST -H "Content-Type: application/json" \
      -d '{"name": "FUZZ", "anotherkey": "anothervalue"}' -fr "error"
```


[Ferobuxter](https://github.com/epi052/feroxbuster) A simple, fast, recursive content discovery tool written in Rust
[Sublist3r](https://github.com/aboul3la/Sublist3r)  Fast Subdomains Enumeration Tool for Penetration Testers

Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu, and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster, and ReverseDNS.

```bash
To list all the basic options and switches use -h switch:
python sublist3r.py -h

To enumerate subdomains of specific domain:
python sublist3r.py -d example.com

To enumerate subdomains of specific domain and show only subdomains which have open ports 80 and 443 :
python sublist3r.py -d example.com -p 80,443

To enumerate subdomains of specific domain and show the results in realtime:
python sublist3r.py -v -d example.com

To enumerate subdomains and enable the bruteforce module:
python sublist3r.py -b -d example.com

To enumerate subdomains and use specific engines such Google, Yahoo and Virustotal engines
python sublist3r.py -e google,yahoo,virustotal -d example.com
```



[Burp Suite Professional:](https://portswigger.net/burp/pro) Toolkit to automate, find and assist web vulnerability discovery and exploitation


[sqlmap](https://sqlmap.org/): Automatic SQL injection and database takeover tool


[Frida](https://frida.re/): Dynamic instrumentation toolkit to intercept and debug software that is closed-source or locked down


[APKLab](https://github.com/APKLab/APKLab): Set of scripts and tools to perform Reverse Engineering on Android applications

```bash
## know how mimikatz windows
## know how windows enumeration mimikatz
## knnow how enumeration windows mimiktaz
```

[mimikatz](https://github.com/ParrotSec/mimikatz): Windows x32/x64 program to extract passwords, hash, PINs, and Kerberos tickets from memory


[Rubeus](https://github.com/GhostPack/Rubeus): Toolset for raw Kerberos interaction and abuses


[Metasploit](https://www.metasploit.com/): Framework to help launching and developing exploits and offensive tasks


[Ghidra](https://ghidra-sre.org/): Software Reverse Engineering (SRE) suite of tools developed by NSA's Research Directorate


[John the Ripper](https://www.openwall.com/john/): Password recovery tool


[hashcat](https://hashcat.net/hashcat/): Fast, efficient and versatile hacking tool that assists offline brute-force attacks


[Wireshark](https://www.wireshark.org/): Network protocol analyzer


[Aircrack-ng](https://www.aircrack-ng.org/): Suite of tools to assess WiFi network security


[ngrok](https://ngrok.com/): Cross-platform application that exposes local server ports to the Internet



[Covenant](https://github.com/cobbr/Covenant): .NET command and control framework


[Nmap](https://nmap.org/): Utility for network discovery and security auditing





[Vega](https://subgraph.com/vega/): Web security scanner and web security testing platform that helps validate SQLi, XSS, etc.


[x64dbg](https://x64dbg.com/): Open-source x64/x32 debugger for Windows


[WinDbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools): Windows default debugger that we use for kernel debugging

Hereby, I’m presenting HackTools, a firefox/chrome extension that summarizes useful commands and helps to build a payload after choosing the required parameters. It might be very useful in a penetration testing engagement. 

[hacktools firefox](https://addons.mozilla.org/en-US/firefox/addon/hacktools/)



[Hacktools chrome](https://chrome.google.com/webstore/detail/hack-tools/cmbndhnoonmghfofefkcccljbkdpamhi)

[Obsidian editor](https://obsidian.md/)


## know how tools converter dwords,16bits,8bits

[convert ip for evading waff](https://www.silisoftware.com/tools/ipconverter.php?convert_from=216.58.215.78)
[hackvector.co.ku (multi tools evasion waf)](https://hackvertor.co.uk/public#)


[aaencode tools javascript evasion](https://utf-8.jp/public/aaencode.html)
[jjencode tools javascript evasion](https://utf-8.jp/public/jjencode.html)
[jsfuck tools javascript evasion](http://www.jsfuck.com/)

## know how tools js minify for evading waf
[js compresor evading waf](http://dean.edwards.name/packer/)
[js yui compresor evading waf](http://yui.github.io/yuicompressor/)

## know how tools scaner vulnerabilities

[OpenVAS](https://www.openvas.org/): Full-featured vulnerability scanner

## know how tools xss
```bash
## know how xss tools
```
[https://github.com/hahwul/dalfox](https://github.com/hahwul/dalfox)
[xsscrapy](https://github.com/DanMcInerney/xsscrapy)
[xsser](https://github.com/epsylon/xsser)
[brutexss](https://github.com/rajeshmajumdar/BruteXSS)
[xssstrike](https://github.com/s0md3v/XSStrike)
[BeEF](https://beefproject.com/): The Browser Exploitation Framework, a penetration testing tool that focuses on the web browser




## know how tools web clone
```bash
## know how tools phising 
## know how tools clone website
## know how clone website tools
```
[GNU Wget](https://www.gnu.org/software/wget/)

[Beef web cloning](https://github.com/AbertayHackers/BeEF)

[Set social engineer toolkit site cloner](https://www.social-engineer.org/framework/se-tools/computer-based/social-engineer-toolkit-set/)

## know how get similar domains for buy for phising

use [urlcrazy](https://github.com/urbanadventurer/urlcrazy) to get similar domains.

## know how tools keylogger

[http_javascript_kelogger](https://github.com/JohnHoder/Javascript-Keylogger)

[beef event loggerls](https://github.com/beefproject/beef)

```Metasploit --> use auxiliary/server/capture/http_javascript_keylogger```



# know how Cheat Sheet sql injection


[sql injection](https://portswigger.net/web-security/sql-injection/cheat-sheet)

## know how tools windows

### know how tools windows privilege escalation

### know how privilege escalation linux

[checklist linux privilege escalation](https://github.com/joseluisinigo/tools-oscp/blob/main/check%20list%20linux%20esc%20priv.md)

[linenum](https://github.com/rebootuser/LinEnum)

[linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

[Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester) LES tool is designed to assist in detecting security deficiencies for given Linux kernel/Linux-based machine. It provides following functionality

[Linux Exploit Suggester 2](https://github.com/joseluisinigo/linux-exploit-suggester-2) Next-generation exploit suggester based on Linux_Exploit_Suggester

[Linux priv checker](https://github.com/joseluisinigo/linuxprivchecker)

[pspy](https://github.com/DominicBreuker/pspy) unprivileged linux process snooping
pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.


### know how tools unquoted privilege escalation windows

[subinACL](https://windows-resource-kit-tools-subinacl-exe.software.informer.com/)
[powersploit powerup.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
[Winpeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
[powerup](https://github.com/HarmJ0y/CheatSheets/blob/master/PowerUp.pdf) muestra los vectores Priv Esc de Windows en función de las configuraciones incorrectas del sistema.  DO NOT use the auto-exploit modules
[windows exploit suggester](https://github.com/joseluisinigo/Windows-Exploit-Suggester) 
This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins.
[sherlck](https://github.com/joseluisinigo/Sherlock)
[watson](https://github.com/joseluisinigo/Watson) Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities.
[jaws](https://github.com/joseluisinigo/JAWS)
JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so 'should' run on every Windows version since Windows 7
[SharpUp](https://github.com/joseluisinigo/SharpUp) is a C# port of various PowerUp functionality. Currently, only the most common checks have been ported; no weaponization functions have yet been implemented.
[psexec](https://github.com/joseluisinigo/tools-oscp/blob/main/psexec.md)  PsExec's most powerful uses include launching interactive command-prompts on remote systems and remote-enabling tools like IpConfig that otherwise do not have the ability to show information about remote systems.
# know how methodology 



## know how methodology privilege escalation
### know how methodology privilege escalation windows

[Methodology unquoted privilege escalation windows](https://www.hackingarticles.in/windows-privilege-escalation-unquoted-service-path/)1. [AlwaysInstallElevated](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated//)
2. [SeBackupPrivilege](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)
3. [DnsAdmins to DomainAdmin](https://www.hackingarticles.in/windows-privilege-escalation-dnsadmins-to-domainadmin/)
4. [SeImpersonatePrivilege](https://www.hackingarticles.in/windows-privilege-escalation-seimpersonateprivilege/)
5. [HiveNightmare](https://www.hackingarticles.in/windows-privilege-escalation-hivenightmare/)
6. [Logon Autostart Execution (Registry Run Keys)](https://www.hackingarticles.in/windows-privilege-escalation-logon-autostart-execution-registry-run-keys/)
7. [Boot Logon Autostart Execution (Startup Folder)](https://www.hackingarticles.in/windows-privilege-escalation-boot-logon-autostart-execution-startup-folder/)
8. [Stored Credentials (Runas)](https://www.hackingarticles.in/windows-privilege-escalation-stored-credentials-runas/)
9. [Weak Registry Permission](https://www.hackingarticles.in/windows-privilege-escalation-weak-registry-permission/)
10. [Unquoted Service Path](https://www.hackingarticles.in/windows-privilege-escalation-unquoted-service-path/)
11. [Insecure GUI Application](https://www.hackingarticles.in/windows-privilege-escalation-insecure-gui-application/)
12. [Weak Service Permissions](https://www.hackingarticles.in/windows-privilege-escalation-weak-services-permission/)
13. [Scheduled Task/Job (T1573.005)](https://www.hackingarticles.in/windows-privilege-escalation-scheduled-task-job-t1573-005/)
14. [Kernel Exploit](https://www.hackingarticles.in/windows-privilege-escalation-kernel-exploit/)
15. [SamAccountSpoofing (CVE-2021–42278)](https://www.hackingarticles.in/active-directory-privilege-escalation-cve-2021-42278/)
16. [SpoolFool](https://www.hackingarticles.in/windows-privilege-escalation-spoolfool/)
17. [PrintNightmare](https://www.hackingarticles.in/windows-privilege-escalation-printnightmare/)
18. [Server Operator Group](https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/)


### know how methodology privilege escalation linux

![image](https://raw.githubusercontent.com/Ignitetechnologies/Linux-Privilege-Escalation/master/privs.png)

1. [Abusing Sudo Rights](https://www.hackingarticles.in/linux-privilege-escalation-using-exploiting-sudo-rights/)
2. [SUID Binaries](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)
3. [Capabilities](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)
4. [Lxd Privilege Escalation](https://www.hackingarticles.in/lxd-privilege-escalation/)
5. [Docker Privilege Escalation](https://www.hackingarticles.in/docker-privilege-escalation/)
6. [Exploiting Cron jobs](https://www.hackingarticles.in/linux-privilege-escalation-by-exploiting-cron-jobs/)
7. [Writable /etc/passwd File](https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/)
8. [Misconfigured NFS](https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/)
9. [Exploiting Wildcard](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/)
10. [LD_Preload Privilege Escalation](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)
11. [Exploiting PATH Variable](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/)
12. [Python Library Hijacking](https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/)
13. [Polkit (CVE 2021-3560)](https://www.hackingarticles.in/linux-privilege-escalation-polkit-cve-2021-3560/)
14. [PwnKit (CVE 2021-4034)](https://www.hackingarticles.in/linux-privilege-escalation-pwnkit-cve-2021-4034/)
15. [DirtyPipe (CVE 2022-0847)](https://www.hackingarticles.in/linux-privilege-escalation-dirtypipe-cve-2022-0847/)


## know how explorer

[Firepwd](https://github.com/lclevy/firepwd)	

## know how tools active directory

oscp

[bloodhound ](https://github.com/joseluisinigo/tools-oscp/blob/main/bloodhound%20active%20directory.md): muestra una imagen del entorno de AD 

[powerview](https://github.com/HarmJ0y/CheatSheets/blob/master/PowerView.pdf) permite la enumeración de un entorno AD


[SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)

[PowerShell Empire](https://github.com/EmpireProject/Empire) Empire is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent


[Covenant](https://github.com/cobbr/Covenant)  Covenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers.

[PowerView](https://github.com/HarmJ0y/CheatSheets/blob/master/PowerView.pdf)

[Rubeus](https://github.com/GhostPack/Rubeus) Rubeus is a C# toolset for raw Kerberos interaction and abuses

[evil-WinRM](https://github.com/joseluisinigo/tools-oscp/blob/main/know%20how%20evilwinrm.md)

[Responder](https://github.com/SpiderLabs/Responder) (Poisoning and Spoofing are not allowed in the labs or on the exam)

[CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)

[Mimikatz](https://github.com/joseluisinigo/tools-oscp/blob/main/know%20how%20mimitkatz.md)


## know how tools pivoting

[chisel](https://github.com/jpillora/chisel)
[shuttle](https://github.com/sshuttle/sshuttle)

## know how courses machines

Compromised both external-facing Active Directory sets in the OSCP lab environment.
TryHackMe — [Active Directory Basics](https://tryhackme.com/room/activedirectorybasics) (for subscribers only)
TryHackMe — [Attacktive Directory](https://tryhackme.com/room/attacktivedirectory)
TryHackMe — [Post-Exploitation Basics](https://tryhackme.com/room/postexploit)
TryHackMe — [Attacking Kerberos](https://tryhackme.com/room/attackingkerberos) (for subscribers only)

[+] Complete the TryHackMe Offensive Pentesting track — This is something you will have to pay for, but it isn’t required. I do recommend it to all novice hackers preparing for the OSCP Exam. Also, you’ll need it if you want to do the TryHackMe labs marked with a [$] below.
Complete the Course Exercises — Offensive Security has received a lot of hate about the lab environment. A lot of the feedback calls it “dated” and complains that it bears no similarities to the exam. I disagree. While yes, it is not like the exam (nor should it be!), it will provide you with a variety of targets that allow you to develop your own methodology.
