---
id: AD09
name: Group managed service account password read by a user account
category: ad-attack
status: todo
severity: high
rank: 9
language: esql
index: logs-windows.security-*
mitre: [T1003, T1552]
data_source: Windows Security event 4662 from domain controllers
suppression:
  fields: [actor]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A gMSA's password is stored in its `msDS-ManagedPassword` attribute and is meant to be retrieved only by the computers allowed to run the service, which read it as their machine accounts (`$`). A person's account reading it means someone holds the "read gMSA password" permission and used it, which hands them the service account's credentials. gMSAs often run privileged services, so this is a direct escalation path.

## Prerequisite
4662 for attribute reads needs a SACL on the gMSA objects (or their OU) auditing read access to `msDS-ManagedPassword`. Confirm the attribute's schema GUID matches the one below in your forest:
```
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "lDAPDisplayName -eq 'msDS-ManagedPassword'" -Properties schemaIDGUID
```

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4662"
| EVAL props = TO_LOWER(TO_STRING(winlog.event_data.Properties)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, ""))
| WHERE props LIKE "*e362ed86-b728-0842-b27d-2dea7a9df218*"      // msDS-ManagedPassword
  AND NOT ENDS_WITH(actor, "$")
  AND NOT (actor IN ("svc-gmsa-management"))                     // accounts that legitimately manage gMSAs
| KEEP @timestamp, host.name, actor, winlog.event_data.SubjectDomainName, winlog.event_data.ObjectName, props
```
LAPS password reads can be added the same way, using the schema GUID of `msLAPS-Password` or `msLAPS-EncryptedPassword` (or `ms-Mcs-AdmPwd` for legacy LAPS, whose GUID differs per forest). Help desks read LAPS passwords routinely, so alert on volume per account rather than on single reads.

## Suppression
Suppress by `actor` for 6h. Alerts missing a key field are not suppressed. One read can log several 4662 events; a different account still alerts.

## Known false positives / exclusions
- Administrators troubleshooting a gMSA with directory tools. Rare; confirm and, if routine, exclude the specific account inline.

## Triage
- Identify which gMSA was read (`ObjectName`) and what it runs. Rotate its password (`Reset-ADServiceAccountPassword`), then remove the read permission from the account that used it.
- Check where that gMSA authenticated afterwards (4624 from unexpected hosts).

## Test
In a lab, grant a test user the right to read a gMSA's password, read it, and confirm the event.
