---
id: W09
name: Active Directory attack tooling signature or recon burst
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1087.002, T1482, T1558.003, T1003, T1069.002, T1018]
data_source: CrowdStrike FDR ProcessRollup2
---
## Why this is high fidelity
Two branches. The tooling branch matches argument signatures of the common AD attack frameworks even when the binary is renamed. The recon branch fires only when one user on one host runs five or more distinct domain-enumeration commands inside ten minutes, which is how operators behave and admins do not.

## Query
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| EVAL tooling = CASE(
        cmd LIKE "*kerberoast*" OR cmd LIKE "*asreproast*" OR cmd LIKE "*asktgt*" OR cmd LIKE "* /ptt*"
     OR cmd LIKE "*sekurlsa*" OR cmd LIKE "*lsadump*" OR cmd LIKE "*dcsync*"
     OR cmd LIKE "*--collectionmethod*" OR cmd LIKE "*invoke-bloodhound*" OR cmd LIKE "*sharphound*"
     OR cmd LIKE "*find /vulnerable*" OR cmd LIKE "*/altname:*" OR cmd LIKE "*certipy*"
     OR cmd LIKE "*get-domainuser*" OR cmd LIKE "*get-netgroupmember*" OR cmd LIKE "*invoke-kerberoast*" OR cmd LIKE "*find-localadminaccess*"
     OR pname IN ("adfind.exe", "rubeus.exe", "mimikatz.exe", "sharphound.exe", "certify.exe", "whisker.exe", "seatbelt.exe", "sharpview.exe", "snaffler.exe"),
     1, 0)
| EVAL recon_cmd = CASE(
        (pname IN ("net.exe", "net1.exe") AND (cmd LIKE "*group*/domain*" OR cmd LIKE "*domain admins*" OR cmd LIKE "*user*/domain*")), "net-domain",
        (pname == "nltest.exe" AND (cmd LIKE "*/dclist*" OR cmd LIKE "*/domain_trusts*")), "nltest",
        (pname IN ("dsquery.exe", "dsget.exe")), "dsquery",
        (pname == "whoami.exe" AND (cmd LIKE "*/priv*" OR cmd LIKE "*/groups*" OR cmd LIKE "*/all*")), "whoami",
        (pname IN ("quser.exe", "qwinsta.exe")), "sessions",
        (pname == "setspn.exe" AND cmd LIKE "*-q*"), "spn",
        (pname == "klist.exe"), "klist",
        (pname == "systeminfo.exe"), "systeminfo",
        (pname == "tasklist.exe"), "tasklist",
        (pname == "arp.exe" AND cmd LIKE "*-a*"), "arp",
        NULL)
| WHERE tooling == 1 OR recon_cmd IS NOT NULL
| STATS tool_hits = SUM(tooling), distinct_recon = COUNT_DISTINCT(recon_cmd), cmds = VALUES(process.command_line), parents = VALUES(process.parent.name)
    BY host.name, user.name, BUCKET(@timestamp, 10 minutes)
| WHERE tool_hits > 0 OR distinct_recon >= 5
```

## Known false positives / exclusions
- Credentialed vulnerability scanners running `net` and `nltest`. Exclude by service account name.
- AD engineers on the admin jump host. Exclude by (host, user) pair only, and review monthly.

## Triage
- Tooling branch: isolate and treat as active intrusion. Recon branch: a normal user should never enumerate Domain Admins; look for I03 from the same host.

## Test
Run five of the recon commands in sequence on a lab host.
