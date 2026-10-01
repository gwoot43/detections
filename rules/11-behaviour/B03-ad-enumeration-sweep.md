---
id: B03
name: Active Directory enumeration sweep - catches BloodHound, SharpHound, ADExplorer, PingCastle by behaviour
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1018, T1087.002, T1069.002, T1049]
data_source: CrowdStrike FDR network connection events
suppression:
  fields: [host.name, process.name]
  duration: 2h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
BloodHound and SharpHound collect by touching the directory and then reaching out to a large share of domain computers for sessions, local admins and loggedon users. ADExplorer, net view loops, PingCastle and similar do the same. The behaviour is one host connecting to a domain controller on LDAP and to many distinct internal hosts on SMB or RPC in a short window. This fires on that shape, so a renamed collector is caught the same way. A normal workstation talks to a few file servers, not most of the estate.

## Query
Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.category == "network" AND network.direction IN ("egress", "outbound")
  AND host.os.type == "windows" AND destination.ip IS NOT NULL
  AND destination.port IN (445, 139, 135, 389, 636, 3268, 3269)
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS smb_targets = COUNT_DISTINCT(CASE(destination.port IN (445, 139, 135), destination.ip, NULL)),
        ldap_targets = COUNT_DISTINCT(CASE(destination.port IN (389, 636, 3268, 3269), destination.ip, NULL)),
        conns = COUNT(*),
        ports = VALUES(destination.port)
    BY host.name, process.name, user.name, BUCKET(@timestamp, 10 minutes)
| WHERE smb_targets >= 40 AND ldap_targets >= 1
```
Requiring at least one LDAP target alongside the SMB fan-out separates directory enumeration from a plain file-server-heavy host. Lower `smb_targets` for small estates.

## Suppression
Suppress by `host.name`, `process.name` for 2h. Alerts missing a key field are not suppressed. Aggregating rule. Collection spans buckets; a different host or process still alerts.

## Known false positives / exclusions
- Legitimate AD tooling run by admins (PingCastle on a schedule, inventory scanners). Exclude the host and process inline in the WHERE clause.
- Management servers, SCCM and endpoint tools that reach many hosts. Exclude those hosts the same way.

## Triage
- A normal user workstation enumerating the directory and sweeping SMB across the estate is reconnaissance for lateral movement. Identify the process and user, isolate the host, and check for the credential access (B08, W01) that usually follows.

## Test
Run a BloodHound collection against a lab domain from a lab workstation.
