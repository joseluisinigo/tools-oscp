# know how impacket

# Impacket usage & detection – 0xf0x.com – Malware, Threat Hunting & Incident Response
Impacket is a collection of Python scripts that can be used by an attacker to target Windows network protocols. This tool can be used to enumerate users, capture hashes, move laterally and escalate privileges. Impacket has also been used by APT groups, in particular Wizard Spider and Stone Panda.

This blog post contains the syntax for running a large number of the Impacket scripts and also the logs that are generated on the target machines.

The Impacket scripts were tested against a Windows 10 machine, any artefacts left behind are included in this report.

Impacket
--------

https://github.com/SecureAuthCorp/impacket

Remote Code Execution:
----------------------

### psexec.py

psexec.py offers psexec like functionality. This can be used to move laterally with captured credentials or via pass the hash attacks.

![impacket](https://neil-fox.github.io/impscreenshots/psexecpy.PNG)

Randomly named generated executable uploaded to C:\\Windows.

Example in above image is named ‘uxVplUAF.exe’

`Md5 - 6983f7001de10f4d19fc2d794c3eb534`

Executable deleted when shell session closed.

Multiple ‘Logon’ and ‘Special Logon’ Event ID’s generated in Windows Security logs.

`Special Logon - 4672`  
`Logon – 4624`

![impacket](https://neil-fox.github.io/impscreenshots/psexecpyseclog.PNG)

Windows System logs contains correlated event for ‘Service Control Manager’.

`Service Control Manager – 7045`

![impacket](https://neil-fox.github.io/impscreenshots/psexecpysyslog1.png)

Event ID 7045 will contain the name of the executable uploaded by psexec.py and the running service that was started.

![impacket](https://neil-fox.github.io/impscreenshots/7045.PNG)

Running processes:

![impacket](https://neil-fox.github.io/impscreenshots/psexecptree.PNG)

![impacket](https://neil-fox.github.io/impscreenshots/psexecpdot.PNG)

### smbexec.py

![impacket](https://neil-fox.github.io/impscreenshots/smbexecpy.PNG)

Two events generated in Windows Security logs.

`Special Logon - 4634`  
`Logon – 4624`

![impacket](https://neil-fox.github.io/impscreenshots/smbexecseclog.PNG)

Windows System logs contain correlated event for ‘Service Control Manager’.

`Service Control Manager – 7045`

![impacket](https://neil-fox.github.io/impscreenshots/smbexecsyslog.PNG)

Event ID 7045 contains the name of the running service that was started.

The Service File Name will contain command which executes a bat file from the %TEMP% directory and then deletes the file from disk. Bat file contains command executed from remote machine.

![impacket](https://neil-fox.github.io/impscreenshots/7045smb.PNG)

Running processes:

![impacket](https://neil-fox.github.io/impscreenshots/smbexecptree.PNG)

![impacket](https://neil-fox.github.io/impscreenshots/smbexecpdot.PNG)

### wmiexec.py

A semi-interactive shell used through Windows Management Instrumentation. It does not require an install of any service/agent on the target server. Runs as Administrator.

![impacket](https://neil-fox.github.io/impscreenshots/wmiexecpy.PNG)

Multiple ‘Logon’ and ‘Special Logon’ Event ID’s generated in Windows Security logs.

`Special Logon - 4672`  
`Logon – 4624`

![impacket](https://neil-fox.github.io/impscreenshots/wmiexecpyseclog.PNG)

Running processes:

![impacket](https://neil-fox.github.io/impscreenshots/wimexecpyprocesstree.PNG)

![impacket](https://neil-fox.github.io/impscreenshots/wmiexecpdot.PNG)

### dcomexec.py

A semi-interactive shell like wmiexec.py but using different DCOM endpoints. Currently supports MMC20.Application, ShellWindows and ShellBrowserWindow objects.

![impacket](https://neil-fox.github.io/impscreenshots/dcomexecpy.PNG)

Multiple ‘Logon’ and ‘Special Logon’ Event ID’s generated in Windows Security logs.

![impacket](https://neil-fox.github.io/impscreenshots/dcomexecpyseclog.PNG)

Running processes:

![impacket](https://neil-fox.github.io/impscreenshots/dcomexecptree.PNG)

![impacket](https://neil-fox.github.io/impscreenshots/wmiexecpdot.PNG)

Kerberos:
---------

### GetUserSPNs.py

This script will try to find and fetch Service Principal Names that are associated with normal user accounts. Output is compatible with John the Ripper and HashCat.

![impacket](https://neil-fox.github.io/impscreenshots/getuserspnspy.PNG)

Windows Security event logs:

`Credential Validation – 4776`  
`Logon – 4624`  
`Kerberos Authentication Service – 4768`  
`Kerberos Service Ticket Operations – 4769`  
`Logoff – 4634`

![impacket](https://neil-fox.github.io/impscreenshots/getuserspnsseclog.PNG)

Windows Secrets:
----------------

### secretsdump.py

Performs various techniques to dump secrets from the remote machine without executing any agent. For SAM and LSA Secrets (including cached creds) the tool will try to read as much info as possible from the registry, then save the hives in the target system (%SYSTEMROOT%\\Temp directory) and then read the rest of the data from this location. For DIT files, it will dump NTLM hashes, Plaintext credentials (if available) and Kerberos keys using the DL\_DRSGetNCChanges() method. It can also dump NTDS.dit via vssadmin executed with the smbexec/wmiexec approach. The script initiates the services required for its working if they are not available (e.g. Remote Registry, even if it is disabled).

![impacket](https://neil-fox.github.io/impscreenshots/secretsdump.PNG)

Six events generated in Windows Security Logs.

`Special Logon - 4672`  
`Logon – 4624`  
`Logoff – 4634`

![impacket](https://neil-fox.github.io/impscreenshots/secretsdumpseclog.PNG)

Two events generated in Windows System logs for ‘Service Control Manager’.

![impacket](https://neil-fox.github.io/impscreenshots/secretsdumpsyslog.PNG)

Contents of Event ID 7040.

![impacket](https://neil-fox.github.io/impscreenshots/7040ntlmrelay.PNG)

![impacket](https://neil-fox.github.io/impscreenshots/7045secretsdump.PNG)

### mimikatz.py

Mini shell to control a remote mimikatz RPC server.

![impacket](https://neil-fox.github.io/impscreenshots/mimikatzpy.PNG)

Nine events generated in Windows Security Logs.

![impacket](https://neil-fox.github.io/impscreenshots/mimikatzpyseclog.PNG)

Two events generated in Windows System logs for ‘Service Control Manager’.

![impacket](https://neil-fox.github.io/impscreenshots/7040mimikatzpy.PNG)

Contents of Event ID 7040.

![impacket](https://neil-fox.github.io/impscreenshots/7040ntlmrelay.PNG)

![impacket](https://neil-fox.github.io/impscreenshots/7045secretsdump.PNG)

### ntlmrelayx.py

This script performs NTLM Relay Attacks, setting an SMB and HTTP Server and relaying credentials to many different protocols (SMB, HTTP, MSSQL, LDAP, IMAP, POP3, etc.). The script can be used with predefined attacks that can be triggered when a connection is relayed (e.g. create a user through LDAP) or can be executed in SOCKS mode.

![impacket](https://neil-fox.github.io/impscreenshots/ntlmrelay1.PNG)

![impacket](https://neil-fox.github.io/impscreenshots/ntlmrelay2.PNG)

Events below generated from SMB Relay Attack; SAM hashes dumped using ntlmrelayx.py.

Eight events generated in Windows Security Logs.

`Special Logon - 4672`  
`Logon – 4624`  
`Logoff – 4634`

![impacket](https://neil-fox.github.io/impscreenshots/ntlmrelayseclog.PNG)

Two events generated in Windows System logs for ‘Service Control Manager’.

![impacket](https://neil-fox.github.io/impscreenshots/ntlmrelaysyslog.PNG)

Contents of Event ID 7040.

![impacket](https://neil-fox.github.io/impscreenshots/7040ntlmrelay.PNG)

![impacket](https://neil-fox.github.io/impscreenshots/7045secretsdump.PNG)

SMB/MSRPC
---------

### smbclient.py

A generic SMB client that will let you list shares and files, rename, upload and download files and create and delete directories, all using either username and password or username and hashes combination.

![impacket](https://neil-fox.github.io/impscreenshots/smbclientpy.PNG)

Two events generated in Windows Security logs.

![impacket](https://neil-fox.github.io/impscreenshots/smbclientpyseclog.PNG)

### lookupsid.py

A tool for brute forcing Windows SID’s which will attempt to identify remote users/groups.

![impacket](https://neil-fox.github.io/impscreenshots/lookupsidspy.PNG)

Two events generated in Windows Security logs.

![impacket](https://neil-fox.github.io/impscreenshots/lookupsidpyseclog.PNG)

### reg.py

Remote registry manipulation tool which provides similar functionality as the REG.EXE Windows utility.

![impacket](https://neil-fox.github.io/impscreenshots/regpy.PNG)

Three events generated in Windows Security Logs.

![impacket](https://neil-fox.github.io/impscreenshots/regpyseclog.PNG)

### rpcdump.py

RPC or Remote Procedure Call is when a computer program causes a procedure to execute in different address space which is coded as a normal procedure call. This script can enumerate those endpoints.

![impacket](https://neil-fox.github.io/impscreenshots/rpcdumppy.PNG)

No Windows event logs generated.

### samrdump.py

An application that communicates with the Security Account Manager Remote interface from the MSRPC suite. It lists system user accounts, available resource shares and other sensitive information exported through this service.

![impacket](https://neil-fox.github.io/impscreenshots/samrdumpy1.PNG)

Three events generated in Windows Security logs.

![impacket](https://neil-fox.github.io/impscreenshots/samrdumpy.PNG)

### services.py

This script can be used to manipulate Windows services through the \[MS-SCMR\] MSRPC Interface. It supports start, stop, delete, status, config, list, create and change.

![impacket](https://neil-fox.github.io/impscreenshots/servicespy.PNG)

Three events generated in Windows Security logs.

![impacket](https://neil-fox.github.io/impscreenshots/servicesseclog.PNG)
