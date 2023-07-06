# **Nmap Results**
```text
Nmap output here
```

<br>
<br>
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
<br>
<br>

# **Post-Exploit Enumeration**
## **Operating Environment**
<details>
  <summary>OS &amp; Kernel</summary>
  
```text
Document here:
  
- Windows
  - "systeminfo" or "Get-ComputerInfo" output
  
- *nix
  - "uname -a" output
  - "cat /etc/os-release" (or similar) output
```
  
</details>

<br>
<br>

<details>
	<summary>Current User</summary>
  
```text
Document here:
 
- Windows
  - "whoami /all" output
  
- *nix
  - "id" output
  - "sudo -l" output
```
  
</details>

<br>
<br>

## **Users and Groups**

<details>
  <summary>Local Users</summary>

```text
Document here any interesting username(s) after running the below commands:
  
- Windows
  - "net user" or "Get-LocalUser" output
  - "net user <username>" or "Get-LocalUser <username> | Select-Object *" to enumerate details about specific users
  
- *nix
  - "cat /etc/passwd" output
```
  
</details>

<br>
<br>

<details>
  <summary>Local Groups</summary>

```text
Document here any interesting group(s) after running the below commands:
  
- Windows
  - "net localgroup" or "Get-LocalGroup" output
  - "net localgroup <group_name>" or "Get-LocalGroupMember <group_name> | Select-Object *" to enumerate users of specific groups
  
- *nix
  - "cat /etc/group" output
  - "cat /etc/group | grep <username>" to check group memberships of specific users
```
  
</details>

<br>
<br>

<details>
  <summary>Domain Users</summary>

```text
Document here any interesting username(s) after running the below commands:
  
- Windows
  - "net user /domain" or "Get-ADUser -Filter * -Properties *" output
  - "net user <username> /domain" or "Get-ADUser -Identity <username> -Properties *" to enumerate details about specific domain users
  - Not a local administrator and can't run PowerShell AD cmdlets?
    - See here: https://notes.benheater.com/books/active-directory/page/powershell-ad-module-on-any-domain-host-as-any-user

- *nix
  - Check if joined to a domain
    - /usr/sbin/realm list -a
    - /usr/sbin/adcli info <realm_domain_name>

  - No credential:

    - Check for log entries containing possible usernames

      - "find /var/log -type f -readable -exec grep -ail '<realm_domain_name>' {} \; 2>/dev/null"
      - Then, grep through each log file and remove any garbage from potential binary files:

        - Using strings: "strings /var/log/filename | grep -i '<realm_domain_name>'"
        - If strings not available, try using od: "od -An -S 1 /var/log/filename | grep -i '<realm_domain_name>'"
        - If od not available, try grep standalone: "grep -iao '.*<realm_domain_name>.*' /var/log/filename"

      - Validate findings:
        - Check if discovered usernames are valid: "getent passwd <domain_username>"
        - If valid, check user group memberships: List "id <domain_username>"
      - Check domain password and lockout policy for password spray feasibility

    - See "Domain Groups", as certain commands there can reveal some additional usernames

   - With a domain credential:

     - If you have a valid domain user credential, you can try "ldapsearch"
     - Dump all objects from LDAP: "ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=*'"
     - Dump all users from LDAP: "ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=account'"


  - If you're root on the domain-joined host:

     - You can try best-effort dumping the SSSD cache:

       - Using strings: "strings /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -i 'ou=.*user.*'" | grep -iv 'disabled' | sort -u
       - If strings not available, try using od: "od -An -S 1 /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -i 'ou=.*user.*'" | grep -iv 'disabled' | sort -u
       - If od not available, try grep standalone: "grep -iao '.*<realm_domain_name>.*' /var/lib/sss/db/cache_<realm_domain_name>.ldb | sed 's/[^[:print:]\r\t]/\n/g' | grep -i 'ou=.*user.*' | grep -iv disabled"

     - You can transfer the SSSD TDB cache for local parsing

       - Default file path: /var/lib/sss/db/cache_<realm_domain_name>.tdb
       - You can dump this file with tools such as "tdbtool" or "tdbdump"
```

</details>

<br>
<br>

<details>
  <summary>Domain Groups</summary>

```text
Document here any interesting group(s) after running the below commands:
  
- Windows
  - "net group /domain" or "Get-ADGroup -Filter * -Properties *" output
  - "net group <group_name> /domain" or "Get-ADGroup -Identity <group_name> | Get-ADGroupMember -Recursive" to enumerate members of specific domain groups
  - Not a local administrator and can't run PowerShell AD cmdlets?
    - See here: https://notes.benheater.com/books/active-directory/page/powershell-ad-module-on-any-domain-host-as-any-user

- *nix

  - Check if joined to a domain
    - /usr/sbin/realm list -a
    - /usr/sbin/adcli info <realm_domain_name>

  - No credential:

    - Enumerate default Active Directory security groups: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#default-active-directory-security-groups

      - "getent group 'Domain Admins@<realm_domain_name>'"
      - "getent group 'Domain Users@<realm_domain_name>'"
      - NOTE: "getent" will only return domain group members that have been cached on the local system, not all group members in the domain
      - This can still build a substantial user list for password spraying (check domain password and lockout policy)

  - With a domain credential:

     - If you have a valid domain user credential, you can try "ldapsearch"
     - Dump all objects from LDAP: "ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=*'"
     - Dump all groups from LDAP: "ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=group'"

  - If you're root on the domain-joined host:

     - You can try dumping the SSSD cache:

       - Using strings: "strings /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -i '<realm_domain_name>'"
       - If strings not available, try using od: "od -An -S 1 /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -i '<realm_domain_name>'"
       - If od not available, try grep standalone: "grep -iao '.*<realm_domain_name>.*' /var/lib/sss/db/cache_<realm_domain_name>.ldb | sed 's/[^[:print:]\r\t]/\n/g' | grep -i 'ou=.*group.*' | grep -i '^CN='"

     - You can transfer the SSSD TDB cache for local parsing

       - Default file path: /var/lib/sss/db/cache_<realm_domain_name>.tdb
       - You can dump this file with tools such as "tdbtool" or "tdbdump"
```
  
</details>

<br>
<br>

## **Network Configurations**

<details>
  <summary>Network Interfaces</summary>

```text
Document here any interesting / additional interfaces:
  
- Windows
  - "ipconfig" or "Get-NetAdapter" output
  
- *nix
  - "ip address" or "ifconfig" output
```
  
</details>

<br>

<details>
  <summary>Open Ports</summary>

```text
Document here any ports listening on loopback or not available to the outside:
  
- Windows
  - "netstat -ano | findstr /i listening" or "Get-NetTCPConnection -State Listen" output
  
- *nix
  - "netstat -tanup | grep -i listen" or "ss -tanup | grep -i listen" output
```
  
</details>

<br>

<details>
  <summary>ARP Table</summary>

```text
If targeting a network and enumerating additional hosts...
Document here:
  
- Windows
  - "arp -a" or "Get-NetNeighbor" output
  
- *nix
  - "ip neigh" or "arp -a" output
```  

</details>

<br>

<details>
  <summary>Routes</summary>

```text
If targeting a network and enumerating additional hosts...
Document here:
  
- Windows
  - "route print" or "Get-NetRoute" output
  
- *nix
  - "ip route" or "route" output
```
  
</details>

<br>

<details>
  <summary>Ping Sweep</summary>

```text
If the host has access to additional routes / interfaces:

  - Look at the IP address space and network mask
  - Find a ping sweep script that will work for the target network
  - Or you could try:
  	- Transfering "nmap" or some other host discover tool to the host
  	- Set up a SOCKS proxy and try a port scan through the foothold
```
  
</details>

<br>
<br>

## **Processes and Services**

<details>
  <summary>Interesting Processes</summary>

```text
First...
Enumerate processes:
  
- Windows
  - "tasklist"
  - "Get-Process"
  - "Get-CimInstance -ClassName Win32_Process | Select-Object Name, @{Name = 'Owner' ; Expression = {$owner = $_ | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue ; if ($owner.ReturnValue -eq 0) {$owner.Domain + '\' + $owner.User}}}, CommandLine | Sort-Object Owner | Format-List"
  
- *nix
  - "ps aux --sort user"
  
Then...
Document here:
  - Any interesting processes run by users/administrators
  - Any vulnerable applications
  - Any intersting command line arguments visible
```
  
</details>

<br>
<br>

<details>
  <summary>Interesting Services</summary>

```text
- Windows
  - First...
    Enumerate services:
  	  - "sc.exe query"
  	  	- Then "sc.exe qc <service-name>"
          - List the configuration for any interesting services
  	  - "Get-CimInstance -ClassName Win32_Service | Select-Object Name, StartName, PathName | Sort-Object Name | Format-List"
  - Then...
  	Check for things like:
  	  - Vulnerable service versions
      - Unquoted service path
      - Service path permissions too open?
        - Can you overwrite the service binary?
        - DLL injection?
  
- *nix
  - First...
  	Enumerate services:
      - "service --status-all" or "systemctl list-units --type=service --state=running"
  - Then...
    Check for things like:
      - Vulnerable service versions
      - Configuration files with passwords or other information
      - Writable unit files
  	  - Writable service binaries  
  
Then...
Document here:
  - Any interesting services or vulnerabilities
  - Any vulnerable service versions
  - Any intersting configuration files
```

</details>

<br>
<br>

## **Scheduled Tasks**

<details>
  <summary>Interesting Scheduled Tasks</summary>

```text
First...
Enumerate scheduled tasks:
  
- Windows
  - schtasks /QUERY /FO LIST /V | findstr /i /c:"taskname" /c:"run as user" /c:"task to run"
  - Get-CimInstance -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_ScheduledTask | Select-Object TaskName, @{Name = 'User' ; Expression = {$_.Principal.UserId}}, @{Name = 'Action' ; Expression = {($_.Actions.Execute + ' ' + $_.Actions.Arguments)}} | Format-List
  
- *nix
  - "crontab -l"
  - "cat /etc/cron* 2>/dev/null"
  - "cat /var/spool/cron/crontabs/* 2>/dev/null"
  
Then...
Document here:
  - Any interesting scheduled tasks
  - Any writable paths in the scheduled task
  - Any intersting command line arguments visible
```
  
</details>

<br>
<br>

## **Interesting Files**
<details>
  <summary>C:\InterestingDir\Intersting-File1.txt</summary>

```text
- Windows
  - Check for writable scripts, writable directories
  - Check for configuration files with passwords and other interesting info
  - Check for scripts with external dependencies that can be overwritten or changed
  - Some interesting places to check
    - Check PATH variable for current user for possible interesting locations
    - Also check for hidden items
    - I reference %SYSTEMDRIVE%, as C: is not always the system volume
        - %SYSTEMDRIVE%\interesting_folder
        - %SYSTEMDRIVE%\Users\user_name
            - Desktop, Downloads, Documents, .ssh, etc
            - AppData (may also have some interesting things in Local, Roaming)
        - %SYSTEMDRIVE%\Windows\System32\drivers\etc\hosts
        - %SYSTEMDRIVE%\inetpub
        - %SYSTEMDRIVE%\Program Files\program_name
        - %SYSTEMDRIVE%\Program Files (x86)\program_name
        - %SYSTEMDRIVE%\ProgramData
        - %SYSTEMDRIVE%\Temp
        - %SYSTEMDRIVE%\Windows\Temp 
  
- *nix
  - Check for SUID binaries
	- "find / -type f -perm /4000 -exec ls -l {} \; 2>/dev/null"
  - Check for writable scripts, writable directories
  - Check for configuration files with passwords and other interesting info
  - Check for scripts with external dependencies that can be overwritten or changed
  - Use strings on interesting binaries to check for relative binary names and $PATH hijacking
  - Some interesting places to check (check for hidden items)
    - Check PATH variable for current user for possible interesting locations
    - /interesting_folder
    - /home/user_name
        - Desktop, Downloads, Documents, .ssh, etc.
    - /var/www/interesting_folder
    - /var/mail/user_name
    - /opt/interesting_folder
    - /usr/local/interesting_folder
    - /usr/local/bin/interesting_folder
    - /usr/local/share/interesting_folder
    - /etc/hosts
    - /tmp
    - /mnt
    - /media
    - /etc
        - Look for interesting service folders
        - Check for readable and/or writable configuration files
        - May find cleartext passwords
```
 
</details>

<br>
<br>

<details>
  <summary>/opt/interesting_dir/interesting-file2.txt</summary>

```text
Add full file contents
Or snippet of file contents
```
 
</details>

<br>
<br>
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
<br>
<br>

# **Persistence**
Document here how you set up persistence on the target
  
<br>
<br>
<br>
<br>

# **Flags**

<details>
  <summary>User</summary>

```text
Flag here
```
</details>

<br>

<details>
  <summary>Root</summary>

```text
Flag here
```
  
</details>

<br>
<br>
