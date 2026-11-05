---
id: SHARES-01
name: Share hunting - one account opening shares on 20+ computers in an hour (Snaffler, PowerView, NetExec spider, ransomware share discovery)
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1135, T1039, T1552.001]
data_source: Windows Security 5140 on the targets
suppression:
  fields: [source.ip, user.name]
  duration: 6h
  missing_fields: do_not_suppress
---
Share hunting lists the shares on every computer it can reach, then opens them to look for something worth taking: passwords in scripts and config files, keys, `unattend.xml`, KeePass databases, finance and HR documents. Ransomware operators do the same sweep to find what to encrypt or steal. Tools that do it:
- **Snaffler**, the usual one: finds every computer in AD, lists its shares, and reads anything that looks like a credential.
- **PowerView** (`Find-DomainShare`, `Find-InterestingDomainShareFile`), **PowerHuntShares**, **SharpShares**, `Invoke-ShareFinder`.
- **NetExec / CrackMapExec** (`--shares`, the `spider_plus` module), **smbmap**, **MANSPIDER**, Impacket's `smbclient.py`.
- Ransomware's built-in share discovery (Conti, LockBit and others list shares with `NetShareEnum`, then encrypt across them), and network scanners that list shares (Advanced IP Scanner, SoftPerfect).

The difference from BloodHound (08): BloodHound only opens `IPC$`, to call services. Share hunting opens the real shares (`C$`, `D$`, `Data`, `Finance`, `IT$`) on many computers. Every share connection is a 5140 on the target, so one account opening shares on 20+ different computers in an hour is the sweep. A normal user opens shares on a handful of file servers.

Run hourly over the last hour.
```esql
FROM logs-yourorg-microsoft-windows*
// Filter for share connections by user accounts
| WHERE event.code == "5140" AND winevt.event_data.share_name IS NOT NULL AND user.name IS NOT NULL
  AND NOT ENDS_WITH(user.name, "$")
// Leave out IPC$ (RPC calls, 08) and the DC shares every user opens at logon
| EVAL share_name = TO_LOWER(winevt.event_data.share_name)
| WHERE NOT share_name IN ("\\\\*\\ipc$", "\\\\*\\sysvol", "\\\\*\\netlogon")
// The address (without the ::ffff: prefix), the account, and each share as computer + share
| EVAL ip = REPLACE(TO_STRING(source.ip), "^::ffff:", ""),
       account = TO_LOWER(user.name),
       share = CONCAT(TO_LOWER(host.name), " ", share_name)
| WHERE account != "anonymous logon"
// Group by address and account: how many computers and shares it opened, and how many were hidden ($) shares
| STATS computers = COUNT_DISTINCT(host.name), shares = COUNT_DISTINCT(share),
        hidden_shares = COUNT_DISTINCT(share) WHERE ENDS_WITH(share_name, "$"),
        sample = TOP(share, 20, "asc"), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY source.ip = ip, user.name = account
// Sanctioned scanners, backup and deployment accounts, as account + address pairs (placeholders)
| WHERE NOT (user.name == "<scanner_account>" AND source.ip IN ("<scanner_ip>"))
// One account opening shares on 20+ computers in the hour (starting value; baseline below)
| WHERE computers >= 20
```
No LogScale version: the Windows logs are in Elastic. Suppress by address and account for 6h.

## Baseline
One query over the last 7 days: per account, address and hour, keeping only the busy hours. Accounts that legitimately peak above the threshold (vulnerability scanners with credentials, backup, SCCM client push, admins' scripts) go into the exclusion as pairs; set the threshold above the highest of the rest.
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "5140" AND winevt.event_data.share_name IS NOT NULL AND user.name IS NOT NULL
  AND NOT ENDS_WITH(user.name, "$")
| EVAL share_name = TO_LOWER(winevt.event_data.share_name)
| WHERE NOT share_name IN ("\\\\*\\ipc$", "\\\\*\\sysvol", "\\\\*\\netlogon")
| EVAL ip = REPLACE(TO_STRING(source.ip), "^::ffff:", ""), account = TO_LOWER(user.name),
       hour = DATE_TRUNC(1 hour, @timestamp)
// Computers each account opened shares on, per address and hour
| STATS computers = COUNT_DISTINCT(host.name, 1000) BY account, ip, hour
// Keep only the busy hours
| WHERE computers >= 10
// second STATS, baseline only: per account and address, its peak hour and how many hours went over 10
| STATS peak = MAX(computers), busy_hours = COUNT(*), first_busy = MIN(hour), last_busy = MAX(hour) BY account, ip
| SORT peak DESC
```

## Which tool ran it
Run 08's Falcon pivot for the alert's address to find the host. Its SMB connections come from the Windows kernel (`System`), so the tool shows up as what the user ran around `first_seen`: `snaffler.exe`, PowerShell with PowerView, a Python process, or an unknown binary.
```logscale
#event_simpleName=ProcessRollup2 aid="<aid>"
| UserName="<user.name>"
| table([@timestamp, FileName, CommandLine, ParentBaseFileName, ImageFileName])
```

## Before turning it on
- 5140 needs "Audit File Share" on the targets, and only computers whose Security logs you collect count. If you collect servers but not workstations, the rule sees the hunt across your servers, which is where the interesting shares are anyway.
- Run the baseline. Expect credentialed vulnerability scans (`C$` and `ADMIN$` everywhere), backup agents and SCCM client push at the top.

## What it misses
- A hunt against a few file servers only. A user reading every folder on one big file server stays under the threshold; 5145 (detailed file share auditing) counts files read, if you have it on the file servers.
- Computers whose logs you don't collect. On the Falcon side, B04 sees one host fanning out to many others on SMB.
- A hunt paced under 20 computers an hour; a second copy over 24 hours with a higher threshold catches slow ones.

## When it fires
`sample` shows which shares were opened. Hidden shares (`C$`, `D$`, `ADMIN$`) across many computers mean the account is an admin on them, which is a lead of its own. Find the tool with the pivot, then look at what it read (5145 on the file servers, if you have it) and assume any credential in those shares is compromised. A burst of share access right before files start changing on those servers is ransomware: contain first.
