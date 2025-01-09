# **Nmap Results**

```text
Nmap output here
```
<br>
<br>

# **Service Enumeration**

## **TCP/00**
Document here:
* Screenshots (web browser, terminal screen)
* Service version numbers
* Document your findings when interacting with the service at various stages
<br>
<br>

## **UDP/00**  
Document here:
* Screenshots (web browser, terminal screen)
* Service version numbers
* Document your findings when interacting with the service at various stages

<br>
<br>

# **Exploit**
Document
here:
* Exploit used (link to exploit)
* Explain how the exploit works against the service
* Any modified code (and why you modified it)
* Proof of exploit (screenshot of reverse shell with target IP address output)

<br>
<br>

# **Post-Exploit Enumeration**
## **Operating Environment**

> [!tldr]- OS &amp; Kernel
>Document here:
>- Windows
>    - `systeminfo` or `Get-ComputerInfo` or `reg.exe query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'` output
>    - Check environment variables:
 >       - CMD: `set`
 >       - PowerShell: `Get-ChildItem Env:\`
>
>- *nix
>    - `uname -a` output
>    - `cat /etc/os-release` (or similar) output
>    - Check environment variables:
>       - `env` or `set`

> [!tldr]- Current User
> Document here:
> - Windows
>     - `whoami /all` output
>   
> - *nix
>     - `id` output
>     - `sudo -l` output

<br>
<br>

## **Users and Groups**

> [!tldr]- Local Users
> Document here any interesting username(s) after running the below commands:
> - Windows
>     - `net user` or `Get-LocalUser` output
>     - `net user <username>` or `Get-LocalUser <username> | Select-Object *` to enumerate details about specific users
>     - Can you dump and pass/crack hashes from SAM using your current access?
> 
> - *nix
>     - `cat /etc/passwd` output

> [!tldr]- Local Groups
> Document here any interesting group(s) after running the below commands:
> - Windows
>     - `net localgroup` or `Get-LocalGroup` output
>     - `net localgroup <group_name>` or `Get-LocalGroupMember <group_name> | Select-Object *` to enumerate users of specific groups
>   
> - *nix
>     - `cat /etc/group` output
>     - `cat /etc/group | grep <username>` to check group memberships of specific users

> [!tldr]- Domain Users (Standalone Domain Controller or Network)
> Document here any interesting username(s) after running the below commands:
> - Windows
>     - `net user /domain` or `Get-ADUser -Filter * -Properties *` output
>     - `net user <username> /domain` or `Get-ADUser -Identity <username> -Properties *` to enumerate details about specific domain users
>     - Not a local administrator and can't run PowerShell AD cmdlets?
>       - See here: https://notes.benheater.com/books/active-directory/page/powershell-ad-module-on-any-domain-host-as-any-user
>     - Can you dump and pass/crack local user / admin hashes from the SAM using your current access?
>     - Can you dump and pass/crack hashes from LSA using your current access?
> 
> - *nix
>     - Check if joined to a domain
>       - /usr/sbin/realm list -a
>       - /usr/sbin/adcli info <realm_domain_name>
> 
>     - No credential:
> 
>       - Check for log entries containing possible usernames
> 
>         - `find /var/log -type f -readable -exec grep -ail '<realm_domain_name>' {} \; 2>/dev/null`
>         - Then, grep through each log file and remove any garbage from potential binary files:
> 
>           - Using strings: `strings /var/log/filename | grep -i '<realm_domain_name>'`
>           - If strings not available, try using od: `od -An -S 1 /var/log/filename | grep -i '<realm_domain_name>'`
>           - If od not available, try grep standalone: `grep -iao '.*<realm_domain_name>.*' /var/log/filename`
> 
>         - Validate findings:
>           - Check if discovered usernames are valid: `getent passwd <domain_username>`
>           - If valid, check user group memberships: List `id <domain_username>`
>         - Check domain password and lockout policy for password spray feasibility
> 
>       - See `Domain Groups`, as certain commands there can reveal some additional usernames
> 
>      - With a domain credential:
> 
>        - If you have a valid domain user credential, you can try `ldapsearch`
>        - Dump all objects from LDAP: `ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=*'`
>        - Dump all users from LDAP: `ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=account'`
> 
> 
>     - If you're root on the domain-joined host:
> 
>        - You can try best-effort dumping the SSSD cache:
> 
>          - Using strings: `strings /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -iE '[ou|cn]=.*user.*'` | grep -iv 'disabled' | sort -u
>          - If strings not available, try using od: `od -An -S 1 /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -iE '[ou|cn]=.*user.*'` | grep -iv 'disabled' | sort -u
>          - If od not available, try grep standalone: `grep -iao '.*<realm_domain_name>.*' /var/lib/sss/db/cache_<realm_domain_name>.ldb | sed 's/[^[:print:]\r\t]/\n/g' | grep -iE '[ou|cn]=.*user.*' | grep -iv disabled`
> 
>        - You can transfer the SSSD TDB cache for local parsing
> 
>          - Default file path: /var/lib/sss/db/cache_<realm_domain_name>.tdb
>          - You can dump this file with tools such as `tdbtool` or `tdbdump`

> [!tldr]- Domain Groups (Standalone Domain Controller or Network)
> Document here any interesting group(s) after running the below commands:
> - Windows
>     - `net group /domain` or `Get-ADGroup -Filter * -Properties *` output
>     - `net group <group_name> /domain` or `Get-ADGroup -Identity <group_name> | Get-ADGroupMember -Recursive` to enumerate members of specific domain groups
>     - Not a local administrator and can't run PowerShell AD cmdlets?
>       - See here: https://notes.benheater.com/books/active-directory/page/powershell-ad-module-on-any-domain-host-as-any-user
> 
> - *nix
> 
>     - Check if joined to a domain
>       - /usr/sbin/realm list -a
>       - /usr/sbin/adcli info <realm_domain_name>
> 
>     - No credential:
> 
>       - Enumerate default Active Directory security groups: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#default-active-directory-security-groups
> 
>         - `getent group 'Domain Admins@<realm_domain_name>'`
>         - `getent group 'Domain Users@<realm_domain_name>'`
>         - NOTE: `getent` will only return domain group members that have been cached on the local system, not all group members in the domain
>         - This can still build a substantial user list for password spraying (check domain password and lockout policy)
> 
>     - With a domain credential:
> 
>        - If you have a valid domain user credential, you can try `ldapsearch`
>        - Dump all objects from LDAP: `ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=*'`
>        - Dump all groups from LDAP: `ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=group'`
> 
>     - If you're root on the domain-joined host:
> 
>        - You can try dumping the SSSD cache:
> 
>          - Using strings: `strings /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -i '<realm_domain_name>'`
>          - If strings not available, try using od: `od -An -S 1 /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -i '<realm_domain_name>'`
>          - If od not available, try grep standalone: `grep -iao '.*<realm_domain_name>.*' /var/lib/sss/db/cache_<realm_domain_name>.ldb | sed 's/[^[:print:]\r\t]/\n/g' | grep -iE '[ou|cn]=.*group.*' | grep -i '^CN='`
> 
>        - You can transfer the SSSD TDB cache for local parsing
> 
>          - Default file path: /var/lib/sss/db/cache_<realm_domain_name>.tdb
>          - You can dump this file with tools such as `tdbtool` or `tdbdump`

<br>
<br>

## **Network Configurations**

> [!tldr]- Network Interfaces
> Document here any interesting / additional interfaces:
>   
> - Windows
>     - `ipconfig` or `Get-NetAdapter` output
>   
> - *nix
>     - `ip address` or `ifconfig` output

>[!tldr]- Open Ports
> Document here any ports listening on loopback or not available to the outside:
>   
> - Windows
>     - `netstat -ano | findstr /i listening` or `Get-NetTCPConnection -State Listen` output
>   
> - *nix
>     - `netstat -tanup | grep -i listen` or `ss -tanup | grep -i listen` output

> [!tldr]- ARP Table
>
> If targeting a network and enumerating additional hosts...
> Document here:
>
> - Windows
>     - `arp -a` or `Get-NetNeighbor` output
> - *nix
>     - `ip neigh` or `arp -a` output

> [!tldr]- Routes
>
> If targeting a network and enumerating additional hosts...
> Document here:
>
> - Windows
>     - `route print` or `Get-NetRoute` output
> - *nix
>     - `ip route` or `route` output

> [!tldr]- Ping Sweep
>
> If the host has access to additional routes / interfaces:
>
>- Look at the IP address space and network mask
>- Find a ping sweep script that will work for the target network
>- Or you could try:
>	- Transfering `nmap` or some other host discover tool to the host
>	- Set up a SOCKS proxy and try a port scan through the foothold

<br>
<br>

## **Processes and Services**

> [!tldr]- Interesting Processes
>
> First...
> Enumerate processes:
>
> - Windows
>     - `tasklist`
>     - `Get-Process`
>     - `Get-CimInstance -ClassName Win32_Process | Select-Object Name, @{Name = 'Owner' ; Expression = {$owner = $_ | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue ; if ($owner.ReturnValue -eq 0) {$owner.Domain + '\' + $owner.User}}}, CommandLine | Sort-Object Owner | Format-List`
>
> - *nix
>     - `ps aux --sort user`
>
> Then...
> Document here:
>    - Any interesting processes run by users/administrators
>    - Any vulnerable applications
>    - Any intersting command line arguments visible

> [!tldr]- Interesting Services
>
> - Windows
>     - First...
>     Enumerate services:
>           - `sc.exe query`
>               - Then `sc.exe qc <service-name>`
>             - List the configuration for any interesting services
>           - `Get-CimInstance -ClassName Win32_Service | Select-Object Name, StartName, PathName | Sort-Object Name | Format-List`
>     - Then...
>       Check for things like:
>           - Vulnerable service versions
>         - Unquoted service path
>         - Service path permissions too open?
>           - Can you overwrite the service binary?
>           - DLL injection?
>
> - *nix
>     - First...
>       Enumerate services:
>         - `service --status-all` or `systemctl list-units --type=service --state=running`
>     - Then...
>     Check for things like:
>         - Vulnerable service versions
>         - Configuration files with passwords or other information
>         - Writable unit files
>             - One-liner to check for writable service unit files: `systemctl list-units --state=running --type=service | grep '\.service' | awk -v FS=' ' '{print $1}' | xargs -I % systemctl status % | grep 'Loaded:' | cut -d '(' -f 2 | cut -d ';' -f 1 | xargs -I % find % -writable 2>/dev/null`
>           - Writable service binaries
>
> Then...
> Document here:
>    - Any interesting services or vulnerabilities
>    - Any vulnerable service versions
>    - Any intersting configuration files


<br>
<br>

## **Scheduled Tasks**

> [!tldr]- Interesting Scheduled Tasks
>
> First...
> Enumerate scheduled tasks:
>
> - Windows
>     - `schtasks /QUERY /FO LIST /V | findstr /i /c:"taskname" /c:"run as user" /c:"task to run"`
>     - `Get-CimInstance -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_ScheduledTask | Select-Object TaskName, @{Name = 'User' ; Expression = {$_.Principal.UserId}}, @{Name = 'Action' ; Expression = {($_.Actions.Execute + ' ' + $_.Actions.Arguments)}} | Format-List`
> - *nix
>     - `crontab -l`
>     - `cat /etc/cron* 2>/dev/null`
>     - `cat /var/spool/cron/crontabs/* 2>/dev/null`
>
> Then...
> Document here:
>    - Any interesting scheduled tasks
>    - Any writable paths in the scheduled task
>    - Any intersting command line arguments visible

<br>
<br>

## **Interesting Files**

> [!tldr]- C:\InterestingDir\Interesting-File1.txt
>
>
> - Windows
>     - Check for writable files and directories
>         - See https://github.com/0xBEN/CTF-Scripts/blob/main/HackTheBox/Axlle/Find-FileAccess.ps1
>     - Check for configuration files with passwords and other interesting info
>     - Check for scripts with external dependencies that can be overwritten or changed
>     - Some interesting places to check
>       - Check `PATH` variable for current user for possible interesting locations
> 	      - CMD: `echo %PATH%`
> 	      - PowerShell: `$env:Path`
>       - Also check for hidden items
>       - PowerShell History File: `(Get-PSReadLineOption).HistorySavePath`
>       - I reference `%SYSTEMDRIVE%`, as `C:` is not always the system volume
>           - `%SYSTEMDRIVE%\interesting_folder`
>           - `%SYSTEMDRIVE%\Users\user_name`
>               - Desktop, Downloads, Documents, .ssh, etc
>               - AppData (may also have some interesting things in Local, Roaming)
>           - `%SYSTEMDRIVE%\Windows\System32\drivers\etc\hosts`
>           - `%SYSTEMDRIVE%\inetpub`
>           - `%SYSTEMDRIVE%\Program Files\program_name`
>           - `%SYSTEMDRIVE%\Program Files (x86)\program_name`
>           - `%SYSTEMDRIVE%\ProgramData`
>           - `%SYSTEMDRIVE%\Temp`
>           - `%SYSTEMDRIVE%\Windows\Temp`
>       - Check the Registry for passwords, configurations, interesting text
>           - `HKEY_LOCAL_MACHINE` or `HKLM`
>           - `HKEY_CURRENT_USER` or `HKCU`
>           - Search the `HKLM` hive recursively for the word `password`
>               - `reg query HKLM /f password /t REG_SZ /s`
>
> - *nix
>     - Check for SUID binaries
>         - `find / -type f -perm /4000 -exec ls -l {} \; 2>/dev/null`
>     - [Check binary capabilities](https://linux-audit.com/kernel/capabilities/overview/)
>         - `getcap -r / 2>/dev/null`
>             - If `getcap` command not found, check `/usr/bin/` or `/usr/sbin
>     - Check for interesting / writable scripts, writable directories or files
>         - `find /etc -writable -exec ls -l {} \; 2>/dev/null`
>         - `find / -type f \( -user $(whoami) -o -group $(whoami) \) -exec ls -l {} \; 2>/dev/null
>     - Check for configuration files with passwords and other interesting info
>     - Check for scripts with external dependencies that can be overwritten or changed
>     - Use strings on interesting binaries to check for relative binary names and $PATH hijacking
>     - Some interesting places to check (check for hidden items)
>       - Check `PATH` variable for current user for possible interesting locations: `echo $PATH`
>       - `/interesting_folder`
>       - `/home/user_name`
>         - `.profile`
>         - `.bashrc`, `.zshrc`
>         - `.bash_history`, `.zsh_history`
>         - Desktop, Downloads, Documents, .ssh, etc.
>         - PowerShell History File: `(Get-PSReadLineOption).HistorySavePath`
>       - `/var/www/interesting_folder`
>       - `/var/mail/user_name`
>       - `/opt/interesting_folder`
>       - `/usr/local/interesting_folder`
>       - `/usr/local/bin/interesting_folder`
>       - `/usr/local/share/interesting_folder`
>       - `/etc/hosts`
>       - `/tmp`
>       - `/mnt`
>       - `/media`
>       - `/etc`
>         - Look for interesting service folders
>         - Check for readable and/or writable configuration files
>         - May find cleartext passwords

> [!tldr]- /opt/interesting_dir/interesting-file2.txt
>
> Add full file contents
> Or snippet of file contents

<br>
<br>

# **Privilege Escalation**  

Document here:
* Exploit used (link to exploit)
* Explain how the exploit works 
* Any modified code (and why you modified it)
* Proof of privilege escalation (screenshot showing ip address and privileged username)

<br>
<br>

# **Persistence**

Document here how you set up persistence on the target

<br>
<br>

# **Flags**

> [!tldr]- User
> 
> `flag goes here`

> [!tldr]- Root
> 
> `flag goes here`
