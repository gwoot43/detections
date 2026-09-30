---
id: I03
name: Kerberoasting: TGS requests with weak encryption at volume
category: identity
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1558.003]
data_source: Windows Security event 4769 from domain controllers
suppression:
  fields: [acct]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Requesting many service tickets for distinct SPNs with RC4 (0x17) encryption from one account in a short window is the on-wire signature of Kerberoasting. Normal clients request a few tickets for the services they actually use, and modern clients prefer AES.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4769"
| EVAL enc = TO_LOWER(TO_STRING(winlog.event_data.TicketEncryptionType)),
       svc = TO_LOWER(winlog.event_data.ServiceName),
       acct = TO_LOWER(winlog.event_data.TargetUserName),
       status = TO_STRING(winlog.event_data.Status)
| WHERE enc IN ("0x17", "0x18", "23", "24")           // RC4 and (optionally) downgraded; keep 0x17 as primary
  AND svc NOT LIKE "*$"                                 // service tickets to computer accounts are normal machine traffic
  AND svc != "krbtgt"
  AND status == "0x0"
| STATS distinct_spns = COUNT_DISTINCT(svc), spns = VALUES(svc), src = VALUES(source.ip)
    BY acct, BUCKET(@timestamp, 10 minutes)
| WHERE distinct_spns >= 8
```
Tune the threshold to your environment. If you have fully moved to AES, alert on any RC4 TGS for a user-account SPN and drop the threshold.

## Suppression
Suppress by `acct` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. Overlapping lookbacks would re-alert.

## Known false positives / exclusions
- Legacy applications and vulnerability scanners that enumerate SPNs. Exclude the scanner account and known legacy service accounts.
- Freshly rebooted app servers requesting many tickets. Baseline first.

## Triage
- Identify the requesting account and source host. The targeted service accounts should have their passwords rotated (long, random) and be moved to Group Managed Service Accounts. Check the source host for W09.

## Test
Run Rubeus or the Kerberoast Atomic (T1558.003) from a lab host.
