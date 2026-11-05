---
id: I01
name: DCSync by a non-domain-controller principal
category: identity
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1003.006]
data_source: Windows Security event 4662 from domain controllers
suppression:
  fields: [subject]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Replicating secrets out of the directory is something only domain controllers and a named sync account (Entra Connect) do. DCSync always needs the Get-Changes-All right, because that is the right that releases password hashes. The plain Get-Changes right is left out on purpose: directory-sync tools (DirSync-based identity and audit products) use it every day and it releases no secrets. Near-zero false positives once the DC and sync accounts are excluded.

## Prerequisite
Audit Directory Service Access must be enabled on DCs with the default SACL on the domain naming context (you confirmed auditing is on). Verify 4662 events actually contain the replication GUIDs before relying on this.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "4662"
| EVAL props = TO_LOWER(TO_STRING(winlog.event_data.Properties)),
       subject = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, user.name))
| WHERE props LIKE "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"   // DS-Replication-Get-Changes-All
    OR props LIKE "*89e95b76-444d-4c62-991a-0facbeda640c*"   // DS-Replication-Get-Changes-In-Filtered-Set
| WHERE NOT (subject LIKE "*$")                                // computer accounts: DCs, and gMSAs such as Entra Cloud Sync's
  AND NOT (subject LIKE "msol_*" OR subject IN ("aadconnect_svc", "svc-aadconnect"))  // your Entra Connect sync account
| KEEP @timestamp, winlog.computer_name, subject, winlog.event_data.SubjectUserSid, winlog.event_data.ObjectName, props, _id, _version, _index
```
Replace the sync account with your real MSOL_ account name. Get it from Entra Connect.

## Suppression
Suppress by `subject` for 1h. Alerts missing a key field are not suppressed. One DCSync run writes event 4662 many times. One alert per account is enough, and the count shows scale.

## Known false positives / exclusions
- The Entra Connect sync account, excluded above.
- Legitimate DCs, excluded by the `$` filter. This also hides a DCSync run under a stolen computer account; AD02 and WE09 cover the paths that get there.
- A product that genuinely needs Get-Changes-All (some password-sync and audit tools). Exclude its account by name after review.

## Triage
- This is a domain-compromise event. Identify the source host of the requesting account (correlate the SID with recent 4624), isolate it, and begin a full AD recovery assessment (assume krbtgt and all hashes are compromised).

## Test
Run the DCSync Atomic (T1003.006) from a lab member server with delegated rights, against a lab DC.
