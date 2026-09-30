---
id: I01
name: DCSync by a non-domain-controller principal
category: identity
status: todo
severity: critical
language: esql
index: logs-windows.security-*
mitre: [T1003.006]
data_source: Windows Security event 4662 from domain controllers
---
## Why this is high fidelity
Replicating directory changes is something only domain controllers and a named sync account (Entra Connect / AAD Connect) do. Any other principal requesting the Get-Changes extended rights is stealing every password hash in the domain. Near-zero false positives once the DC and sync accounts are excluded.

## Prerequisite
Audit Directory Service Access must be enabled on DCs with the default SACL on the domain naming context (you confirmed auditing is on). Verify 4662 events actually contain the replication GUIDs before relying on this.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4662"
| EVAL props = TO_LOWER(TO_STRING(winlog.event_data.Properties)),
       subject = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, user.name))
| WHERE props LIKE "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"   // DS-Replication-Get-Changes
    OR props LIKE "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"   // DS-Replication-Get-Changes-All
    OR props LIKE "*89e95b76-444d-4c62-991a-0facbeda640c*"   // Get-Changes-In-Filtered-Set
| WHERE NOT (subject LIKE "%$")                                // exclude computer accounts (DCs end in $)
  AND NOT (subject IN ("msol_*", "aadconnect_svc", "svc-aadconnect"))  // exclude your Entra Connect sync account
| KEEP @timestamp, host.name, subject, winlog.event_data.SubjectUserSid, winlog.event_data.ObjectName, props
```
Replace the sync account with your real MSOL_ account name. Get it from Entra Connect.

## Known false positives / exclusions
- The Entra Connect sync account, excluded above. Azure AD Connect Health.
- Legitimate DCs, excluded by the `$` filter.

## Triage
- This is a domain-compromise event. Identify the source host of the requesting account (correlate the SID with recent 4624), isolate it, and begin a full AD recovery assessment (assume krbtgt and all hashes are compromised).

## Test
Run the DCSync Atomic (T1003.006) from a lab member server with delegated rights, against a lab DC.
