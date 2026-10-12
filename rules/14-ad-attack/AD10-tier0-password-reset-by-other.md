---
id: AD10
name: Password of a Tier-0 account reset by another account
category: ad-attack
status: todo
severity: high
rank: 10
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1098]
data_source: Windows Security event 4724 from domain controllers
suppression:
  fields: [target]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An attacker with reset-password rights over a privileged account does not need its password: they set a new one and log in. Event 4724 records a reset performed by someone other than the account owner (owners changing their own password produce 4723). Resets of Tier-0 accounts should happen only through your privileged-access tooling, so any other reset is worth a call.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "4724"
| EVAL actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       target = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
       tsid = TO_STRING(winlog.event_data.TargetSid)
| WHERE actor != target
  AND (target LIKE "adm-*" OR target LIKE "da-*" OR target LIKE "*-admin" OR target LIKE "svc-tier0*"
       OR target == "administrator" OR tsid LIKE "S-1-5-21-*-500"
       OR target == "krbtgt" OR target LIKE "msol_*" OR target LIKE "breakglass*")   // your Tier-0 naming
  AND NOT (actor IN ("svc-pam"))                                                    // your PAM / password vault account
| KEEP @timestamp, winlog.computer_name, actor, target, tsid, winlog.event_data.SubjectDomainName, _id, _version, _index
```
Swap the name patterns for your own Tier-0 naming. The built-in Administrator is caught by its RID (500) whatever it is renamed to.

## Suppression
Suppress by `target` for 6h. Alerts missing a key field are not suppressed. A reset can be retried; a different target still alerts.

## Known false positives / exclusions
- Planned krbtgt rotations are a 4724 on `krbtgt` by an admin. Expected twice per rotation; confirm with the change ticket.
- Break-glass password rotation by the identity team. Same.

## Triage
- Confirm with the account owner and the actor. If unplanned, reset the account again through PAM, revoke its sessions, and find out how the actor obtained reset rights over it (check the target's ACL and AD02, I11).

## Test
Reset a lab Tier-0 test account's password from another admin account.
