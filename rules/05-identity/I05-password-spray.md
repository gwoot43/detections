---
id: I05
name: Password spray against Active Directory (failed logons across many accounts from one source)
category: identity
status: todo
severity: high
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1110.003]
data_source: Windows Security event 4625 (failed logon), on domain controllers and member servers
suppression:
  fields: [source.ip]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Spray is defined by breadth, not depth: one source failing against many distinct accounts with few attempts each, so it stays under per-account lockout. Alerting on the breadth is far higher fidelity than per-account failure counting, and it fires before the spray reaches the lockout threshold.

This is the on-premises rule. Entra ID spray and brute force are S13 (one account from one IP), S14 (one account from many IPs) and S15 (many accounts from many IPs), which also flag a guess that found the right password even when MFA or Conditional Access then stopped the sign-in.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE event.code == "4625" AND source.ip IS NOT NULL
  AND NOT CIDR_MATCH(source.ip, "127.0.0.0/8", "::1/128")       // local logons (IIS, Exchange) carry no remote source
| EVAL acct = TO_LOWER(winlog.event_data.TargetUserName)
| WHERE acct != "" AND acct != "-" AND NOT ENDS_WITH(acct, "$")
| STATS failed_users = COUNT_DISTINCT(acct), dest_hosts = VALUES(winlog.computer_name)
    BY source.ip, BUCKET(@timestamp, 30 minutes)
| WHERE failed_users >= 10
```

## Suppression
Suppress by `source.ip` for 4h. Alerts missing a key field are not suppressed. Aggregating rule. A spray spans several buckets; a different source still alerts.

## Known false positives / exclusions
- A misconfigured application or a shared kiosk retrying stale credentials against many accounts. Exclude by source IP after confirming.
- A Citrix, RDS or VPN gateway that relays many users' logons appears as one `source.ip`. Exclude the gateway IPs inline.

## Triage
- Map `source.ip` to a host and find who is logged on to it. A workstation spraying the domain is compromised: isolate it.
- Check whether any of the sprayed accounts then logged on successfully from the same source (4624 from `source.ip`) and treat those accounts as compromised: reset passwords and check them for lateral movement (W08, B05).

## Test
Validate on historical logon data or run a controlled spray against lab accounts.
