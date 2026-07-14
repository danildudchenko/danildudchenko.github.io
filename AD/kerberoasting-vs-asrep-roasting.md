# Kerberoasting vs AS-REP Roasting

Two Active Directory attacks that both produce offline-crackable hashes —
but with different requirements, different targets, and different
misconfigurations to exploit.

---

## Kerberoasting

Kerberoasting targets accounts that have a **Service Principal Name (SPN)**
configured. SPNs are how Kerberos maps services to accounts — they're
legitimate and common in any AD environment.

When you request a Kerberos service ticket (TGS) for an SPN, the Domain
Controller encrypts it using the service account's password hash. That
encrypted ticket lands in your hands and can be cracked offline — no
interaction with the target account required after that point.

**Requirement:** any valid set of domain credentials.

```bash
impacket-GetUserSPNs domain.local/user:pass -request -outputfile hashes.txt
hashcat -m 13100 hashes.txt rockyou.txt   # RC4
hashcat -m 19700 hashes.txt rockyou.txt   # AES-256
```

This works because requesting service tickets is **normal Kerberos behavior** — every domain user can do it. The vulnerability isn't in the protocol, it's in service accounts being assigned weak passwords.

---

## AS-REP Roasting

AS-REP Roasting targets accounts with **"Do not require Kerberos pre-authentication"** enabled. Pre-authentication is the step where a user proves they know their password before the DC issues a TGT. Disable it, and anyone can request that TGT unauthenticated — receiving an AS-REP encrypted with the
account's password hash.

**Requirement:** none. No domain credentials needed.

```bash
impacket-GetNPUsers domain.local/ -no-pass -usersfile users.txt -format hashcat
hashcat -m 18200 hashes.txt rockyou.txt
```

This opens an interesting attack chain even before gaining any foothold: gather potential usernames through OSINT, generate extended wordlists with tools like **Username Anarchy**, validate which usernames exist in the domain via Kerberos error codes using **Kerbrute**, then run AS-REP Roasting against confirmed accounts.

---

## Targeted Kerberoasting

Worth mentioning separately: if you already have **write privileges over another AD object** (GenericWrite, GenericAll, WriteProperty on `servicePrincipalName`) you can add an SPN to an account that didn't have one, Kerberoast it, then remove the SPN afterward.

```powershell
# Add SPN (with write rights)
Set-DomainObject -Identity target_user -Set @{servicePrincipalName="http/svc"}

# Kerberoast it
impacket-GetUserSPNs domain.local/user:pass -request -outputfile targeted.txt

# Clean up
Set-DomainObject -Identity target_user -Clear servicePrincipalName
```

BloodHound will surface these write-privilege paths — look for **GenericWrite** edges pointing at accounts worth targeting.

---

## Quick Reference

| | Kerberoasting | AS-REP Roasting |
|--|--------------|-----------------|
| Requires creds | Yes — any domain user | No |
| Target | Accounts with SPN set | Accounts with pre-auth disabled |
| Hash type (hashcat) | `-m 13100` (RC4) / `-m 19700` (AES) | `-m 18200` |
| Misconfiguration | Weak password on service account | Pre-auth disabled on user account |
| Tool | `GetUserSPNs.py` | `GetNPUsers.py` |

---

## Mitigation

- **Kerberoasting:** enforce strong, long, randomly generated passwords on all service accounts. Use **Group Managed Service Accounts (gMSA)** — passwordsare managed and rotated automatically by AD.
- **AS-REP Roasting:** audit accounts with pre-authentication disabled. There is almost never a legitimate reason for this setting.
- **Targeted Kerberoasting:** audit and minimize write permissions in AD. Review GenericWrite/GenericAll ACLs regularly with BloodHound.
