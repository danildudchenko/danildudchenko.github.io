---
layout: post
title: "Blind SQL Injection with Conditional Errors (Oracle) — PortSwigger Web Security Academy"
date: 2026-08-26
categories: [web-security, sql-injection]
tags: [sqli, blind-sqli, oracle, burp-suite, portswigger]
---

## Overview

This writeup covers solving PortSwigger's **"Blind SQL injection with conditional errors"** lab. Unlike the earlier boolean-based lab in this series (which used a visible "Welcome back" message as the true/false signal), this application shows **no visible output and no obvious error messages** — the only way to extract data is by forcing the *database itself* to throw an error on purpose, and using "did the request error out" as the oracle.

The injection point is the `TrackingId` cookie, used directly in a server-side SQL query with no sanitization.

## Step 1 — Confirming the injection point

Standard first move: append a single quote and see what breaks.

```
Cookie: TrackingId=dbYNOgVgdioaBAt0'
```

No visible error, no obvious change in the response — confirming this is genuinely **blind**. No SQL error text leaks to the page, so I couldn't just read a database error message directly like in a classic error-based injection. This meant I needed to build my own oracle rather than relying one.

## Step 2 — Fingerprinting the database engine

Before building any extraction technique, I needed to know *which* database engine I wasr forcing conditional errors differs significantly between Oracle, MySQL, PostgreSQL, andMSSQL.

I used a database-specific quirk to test this: **Oracle requires every `SELECT` to have a `FROM` clause**, even for a bare literal — unlike MySQL, PostgreSQL, and MSSQL, which all tolerate a `SELECT` with no
`FROM` at all. Oracle's workaround for this is a special one-row, one-column pseudo-tablcally so you can `SELECT` a literal without querying real data.

Test payload:
```
dbYNOgVgdioaBAt0' AND (SELECT 'a' FROM DUAL)='a
```

This came back **clean, no error** — meaning `DUAL` exists and the query is syntactically valid. That's a strong positive signal for Oracle specifically: if this had been MySQL/PostgreSQL/MSSQL, `FROM DUAL`
would likely be nonsense (`DUAL` isn't a special table on those engines) and would be moed.

Combined with the fact that a *bare* `SELECT 'a'` (no `FROM` at all) would fail on Oracl, this gave me confidence I was looking at an **Oracle** backend before writing a singlecharacter-extraction payload.

## Step 3 — Building the conditional-error oracle

With the engine identified, I used Oracle's documented conditional-error pattern: a `CASE WHEN` expression that deliberately triggers a **division-by-zero error** when a condition is true, and returns a
harmless value when it's false.

```sql
(SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL)
```

- `TO_CHAR(1/0)` — Oracle needs `1/0` wrapped in `TO_CHAR()` for this to reliably throw rather than behaving inconsistently.
- `ELSE 'a'` — a harmless fallback when the condition is false, so the query completes normally.

I proved the oracle worked by toggling a known true/false condition and confirming I got **different results** for each:

```
dbYNOgVgdioaBAt0' AND (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL)=
```
`1=2` (false) → no error, normal response.
`1=1` (true) → error response.                                                                                                                                                                              
Two different, consistent outcomes for a known true/false condition — that's a working oracle: **error = true, normal response = false**.                                                                   
## Step 4 — Building the real extraction condition                                                                                                                                                          
With the oracle confirmed, I replaced the placeholder `1=2` with a real per-character password test, using Oracle's `SUBSTR()` function (**not** `SUBSTRING` — that's MySQL/MSSQL/PostgreSQL syntax and doesexist in Oracle):
                                                                                                                                                                                                            ```sql
dbYNOgVgdioaBAt0' AND (SELECT CASE WHEN (SUBSTR((SELECT Password FROM Users WHERE Username='Administrator'),§§,1)='§§') THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL)='a                                        ```
                                                                                                                                                                                                            ## Debugging detour — "it always errors, no matter what I try"
                                                                                                                                                                                                            My first attempt at this looked correct on paper but errored on *every single request*, racter — which is itself a useful diagnostic signal. If a conditional-error payload errors unconditionally, that's almost always a **syntax bug in the payload itself**, not confirmation that every character matches.                                                                                
The actual bug, once I inspected the raw request:                                                                                                                                                           
```                                                                                                                                                                                                         SUBSTR((SELECT password FROM users WHERE Username='administrator'),,1)=''
```                                                                                                                                                                                                         
The position argument between the commas (`,,1)`) was **empty**, and the compared character (`=''`) was also empty — leftover artifacts from copying an Intruder payload template without substituting real values for the `§§` markers. `SUBSTR(str, , 1)` is missing a required argument — a hard letely independent of the actual character being tested. That's exactly why it looked like "always true."

Fix: always supply real values in place of both markers before testing manually. Working single-character test (position 1, character `'a'`):

```sql
SUBSTR((SELECT password FROM users WHERE Username='administrator'),1,1)='a'
```

Also worth noting: this lab's actual schema uses **lowercase** identifiers (`users`, `password`) and a **lowercase** value (`'administrator'`) — Oracle identifiers are case-insensitive by default, but string
*values* are case-sensitive, so getting `'Administrator'` vs `'administrator'` wrong silt causing any error at all.

## Step 5 — Automating full extraction with Burp Intruder

Manually testing one character at a time doesn't scale to a 20-character password. Autom

```
Cookie: TrackingId=dbYNOgVgdioaBAt0' AND (SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE Username='administrator'),§§,1)='§§') THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL)='a
```

- **Attack type**: Cluster bomb — needed because two independent variables are being tescter). A Sniper attack only varies one payload position at a time and can't cover everyposition×character combination in a single run.
- **Payload position 1** (character index): numeric list, `1`–`20`.
- **Payload position 2** (character guess): `a-z0-9`.
- **Signal to watch for**: HTTP 500 / error response = match at that position; normal re

Reconstructing the password from whichever character produced an error at each position  password, one character at a time — entirely through a binary error/no-error signal,without ever seeing the actual data in a response body.

## Key takeaways

- When an app gives you zero visible feedback, you're not stuck — you can build your own oracle by forcing the database to fail in a way that's externally observable (HTTP status/response difference), even
without any error message ever being *shown* to you.
- Fingerprint the database engine **before** picking a conditional-error technique — the syntax (and even whether `1/0` errors at all) differs significantly between Oracle, MySQL, PostgreSQL, and MSSQL.
- If a payload fails *unconditionally* regardless of what you change, suspect a syntax bn before suspecting the underlying logic.
