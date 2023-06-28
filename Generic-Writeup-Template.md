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
## **Current User**
<details>
	<summary>Click to expand</summary>
  
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

## **OS &amp; Kernel**

<details>
  <summary>Click to expand</summary>
  
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

## **Users**

<details>
  <summary>Click to expand</summary>

```text
Document here any interesting username after running the below commands:
  
- Windows
  - Domain:
  	- "net user /domain" or "Get-ADUser -Filter *" output
  
  - Workgroup:
  	- "net user" or "Get-LocalUser" output
  
- *nix
  - "cat /etc/passwd" output
```
  
</details>

<br>
<br>

## **Groups**

<details>
  <summary>Click to expand</summary>

```text
Document here any interesting groups after running the below commands:
  
- Windows
  - Domain:
  	- "net group /domain" or "Get-ADGroup -Filter *" output
  
  - Workgroup:
  	- "net localgroup" or "Get-LocalGroup" output
  
- *nix
  - "cat /etc/group" output
```
  
</details>

<br>
<br>

## **Network**

<details>
  <summary>Interfaces</summary>

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
  <summary>Open Ports</summary>

```text
Document here any ports listening on loopback or not available to the outside:
  
- Windows
  - "netstat -ano | findstr /i listening" or "Get-NetTCPConnection -State Listen" output
  
- *nix
  - "netstat -tanup | grep -i listen" output
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

## **Processes**

<details>
  <summary>Click to expand</summary>

```text
First...
Enumerate processes:
  
- Windows
  - "tasklist"
  - "Get-Process"
  - "Get-CimInstance -ClassName Win32_Process | Select-Object Name, @{Name = 'Owner' ; Expression = {$owner = $_ | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue ; if ($owner.ReturnValue -eq 0) {$owner.Domain + '\' + $owner.User}}}, CommandLine | Sort-Object Owner | Format-List"
  
- *nix
  - "ps auxf"
  
Then...
Document here:
  - Any interesting processes run by users/administrators
  - Any vulnerable applications
  - Any intersting command line arguments visible
```
  
</details>

<br>
<br>

## **Services**

<details>
  <summary>Click to expand</summary>

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
  
- *nix
  - First...
  	Enumerate services:
      - "service --status-all" or "systemctl list-units"
  - Then...
    Check for things like:
      - Vulnerable service versions
      - Configuration files
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
  <summary>Click to expand</summary>

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
  <summary>File 1</summary>

```text
- Windows
  - Check for writable scripts, writable directories
  - Check for configuration files with passwords and other interesting info
  - Check for scripts with external dependencies that can be overwritten or changed
  - Some interesting places to check
    - Check PATH variable for current user for possible interesting locations
    - I reference %SYSTEMDRIVE%, as C: is not always the system volume
    - Also check for hidden items
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
  <summary>File 2</summary>

```text

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
