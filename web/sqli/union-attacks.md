---
layout: post
title: "SQL UNION Attacks - PortSwigger Labs Walkthrough"
date: 2026-06-30
categories: [web, sql-injection]
---

SQL injection is one of the oldest web vulnerabilities out there, but it still shows up everywhere.
This post covers UNION-based SQL injection - what it is, how to approach it, and the payloads
I used to solve PortSwigger labs.

## What is a UNION attack

UNION attacks are useful when the application is vulnerable to SQL injection AND returns query
results in the response. That second part matters - if nothing is reflected back, UNION attacks
won't work and you need to look at blind techniques instead.

The idea is simple: we extend the original SELECT statement with our own UNION SELECT to pull
additional data from other tables.

Take a product search page. The backend query might look like this:

```sql
SELECT name, description FROM products WHERE category = 'Electronics'

If the category parameter is injectable, we can append our own query and pull data from a
completely different table. The app thinks it is returning product names - it is actually
returning usernames and passwords:

SELECT name, description FROM products WHERE category = 'Electronics'
UNION SELECT username, password FROM users--'

Step 1 - Determine the number of columns

Before anything works, our injected query must return the same number of columns as the original
query. This is a hard requirement - if the column count does not match, the database throws an
error and nothing comes back.

The cleanest way to figure this out is the NULL method. We keep adding NULLs until the page
stops throwing an error:

' UNION SELECT NULL,NULL,NULL--

NULL works for any data type so it avoids type mismatch errors. We just increment the count
until it lands. When the page loads normally, that is our column count.

The ORDER BY method is an alternative - increment the number until the page breaks, then subtract
one. Both work, NULL is just more reliable.

One thing to keep in mind for Oracle databases - every SELECT must have a FROM clause. Oracle has
a built-in dummy table called dual for exactly this purpose, so the payload becomes
' UNION SELECT NULL FROM DUAL--.

Step 2 - Find columns that accept string data

Knowing the column count is not enough. We also need to know which of those columns can hold
string data, because that is what we want to extract - usernames, passwords, version info, etc.
Trying to put a string into a numeric column causes a type error.

We test this by replacing one NULL at a time with a string value and watching what happens:

' UNION SELECT NULL,'test',NULL--

If the page loads normally and we see our test string somewhere in the response, that column
accepts strings and we can use it to pull real data out.

Step 3 - Extract data

Once we know the column count and which columns accept strings, we can pull actual data:

' UNION SELECT username, password FROM users--

Sometimes we only have one usable string column but want to retrieve multiple values. We can
concatenate them into a single string using the || operator with a separator in between:

' UNION SELECT null, username || '~' || password FROM users--

The ~ just acts as a delimiter so we can split the values apart after.

Database enumeration

Before going straight for the end goal - whether that is RCE, privilege escalation, or something
else - it is worth mapping out the database first. Databases often hold credentials for other
services, internal tools, or admin panels that give faster access than any exploit would.

The first thing to grab is the database version, since syntax varies between MySQL, MSSQL,
PostgreSQL, and Oracle. For MySQL and Microsoft the payload is @@version, for Oracle it is
banner FROM v$version.

After that the approach is the same across databases. Query the information schema to list all
tables, then query it again to list columns for any table that looks interesting, then pull the
data. On Oracle the same information lives in all_tables and all_tab_columns instead of the
information schema.

The table and column names from the labs had random suffixes like users_cboybi and
password_wmcvuo - PortSwigger randomizes these so you cannot just guess them. That is the point
of the enumeration step, you always have to discover the actual names before you can extract
anything.

Key takeaways

- UNION attacks only work when results are reflected in the response
- Column count and data types must match the original query exactly
- Find which columns accept strings before trying to extract real data
- Enumerate the database before going for the end goal - credentials might get you there faster
- Syntax differs between databases, always fingerprint the backend first
