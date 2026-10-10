---
id: W09
name: Active Directory attack tool signature (SharpHound/BloodHound, Rubeus, Certify/Certipy, PowerView, AdFind and similar) by argument or binary name
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1087.002, T1482, T1558.003, T1003, T1069.002, T1018]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
One branch: argument signatures and binary names of the common AD attack frameworks. The arguments (`--collectionmethod`, `asktgt`, `/ptt`, `find /vulnerable`, `/altname:`, PowerView cmdlets) are specific to the tools and match even when the binary is renamed; the binary names catch unmodified copies. Admins do not run these on a normal working day.

Other rules own the neighbouring signals, so they are not repeated here:
- Discovery-command bursts and domain-enumeration arguments (`net group /domain`, `nltest /dclist`, `whoami /priv`, `setspn -q`) are B09.
- Mimikatz credential-dumping modules (`sekurlsa`, `lsadump`, `dcsync`) are W01 and I01.
- Kerberoasting and AS-REP roasting are caught by behaviour in I03, I04 and I13, and by the honey accounts in D01.

## Query
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| EVAL tooling = CASE(
        cmd LIKE "*asktgt*" OR cmd LIKE "* /ptt*"
     OR cmd LIKE "*--collectionmethod*" OR cmd LIKE "*invoke-bloodhound*" OR cmd LIKE "*sharphound*"
     OR cmd LIKE "*find /vulnerable*" OR cmd LIKE "*/altname:*" OR cmd LIKE "*certipy*"
     OR cmd LIKE "*get-domainuser*" OR cmd LIKE "*get-netgroupmember*" OR cmd LIKE "*find-localadminaccess*"
     OR pname IN ("adfind.exe", "rubeus.exe", "mimikatz.exe", "sharphound.exe", "certify.exe", "whisker.exe", "seatbelt.exe", "sharpview.exe", "snaffler.exe"),
     1, 0)
| WHERE tooling == 1
// user.name is DOMAIN\user or user depending on enrichment; group on the bare, lowercased name
| EVAL user.name = TO_LOWER(MV_LAST(SPLIT(user.name, "\\")))
| STATS tool_hits = SUM(tooling), cmds = VALUES(process.command_line), parents = VALUES(process.parent.name),
        host.name = VALUES(host.name)
    BY host.id, user.name, BUCKET(@timestamp, 10 minutes)
```

## Suppression
Suppress by `host.id`, `user.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. Overlapping lookbacks would re-alert. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on, so it is an output column, not a key.

## Known false positives / exclusions
- Authorised penetration tests and AD security assessments (the security team running SharpHound, Snaffler or Seatbelt). Exclude by (host, user) pair only for the engagement window.
- AD engineers who keep AdFind on the admin jump host. Exclude by (host, user) pair only, and review monthly.

## Triage
- Isolate and treat as active intrusion unless it matches a scheduled engagement. Read `cmds` for the target (users, groups, certificate templates, ticket requests), check the host for credential access (W01, B08) and the domain for what followed (I03, I09, I12).

## Test
Run SharpHound with `--CollectionMethod Default`, or `Rubeus.exe asktgt` against a lab account, on a lab host.
