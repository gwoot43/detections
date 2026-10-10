---
id: I06
name: Privileged account interactive logon to a workstation or unusual host
category: identity
status: todo
severity: high
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1078.002, T1021]
data_source: Windows Security event 4624
suppression:
  fields: [acct, dest]
  duration: 8h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Tier-0 accounts should log on only to domain controllers and privileged access workstations. A Domain Admin logging on interactively (type 2, 10 RDP, or with credentials cached type 11) to an ordinary workstation is either a tiering violation or stolen credentials in use. Both need action.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "4624"
| EVAL acct = TO_LOWER(winlog.event_data.TargetUserName),
       acct_domain = TO_LOWER(COALESCE(winlog.event_data.TargetDomainName, "")),
       logon_type = TO_STRING(winlog.event_data.LogonType),
       dest = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, ".")))   // with event forwarding, host.name is the collector
// your Tier-0 account naming convention, e.g. adm-, da-, _admin; adjust to reality
| WHERE (acct LIKE "adm-*" OR acct LIKE "da-*" OR acct LIKE "*-admin" OR acct LIKE "svc-tier0*" OR acct IN ("administrator"))
  AND logon_type IN ("2", "10", "11")
  AND acct_domain != dest                                         // local accounts (the built-in local Administrator) are not Tier-0
// exclude the sanctioned Tier-0 hosts: DCs and PAWs
| WHERE NOT (dest LIKE "dc*" OR dest LIKE "*-dc*" OR dest LIKE "paw-*" OR dest LIKE "adminws-*")
| KEEP @timestamp, dest, acct, acct_domain, logon_type, source.ip, source.domain
```
`source.ip` and `source.domain` hold the logon's client address and workstation name; the integration moves them out of `winlog.event_data`.
Replace the naming conventions with your own, or list the Tier-0 account names inline.

## Suppression
Suppress by `acct`, `dest` for 8h. Alerts missing a key field are not suppressed. Interactive sessions reconnect through the day.

## Known false positives / exclusions
- A break-glass account used during an incident, on the incident host. Expect it and document it.
- New PAWs not yet in the naming pattern. Fix the pattern.
- The local built-in Administrator (for example a LAPS account used by the help desk) is excluded because its domain is the host itself.

## Triage
- Contact the account owner. If unexpected, isolate the destination host (credential exposure) and rotate the account.

## Test
Log on interactively with a lab Tier-0 account to a lab workstation.
