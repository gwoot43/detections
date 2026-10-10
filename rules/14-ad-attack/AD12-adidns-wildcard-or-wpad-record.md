---
id: AD12
name: ADIDNS wildcard, WPAD or ISATAP record created by a user account
category: ad-attack
status: todo
severity: medium
rank: 12
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1557]
data_source: Windows Security event 5137 from domain controllers
suppression:
  fields: [op_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
By default any authenticated user can add records to AD-integrated DNS zones. A wildcard record (`*`) answers every name that does not exist, and a `wpad` or `isatap` record lets the creator answer proxy auto-discovery, so either can redirect clients to a host that captures or relays their credentials. Legitimate records are created by the DNS service on behalf of machines (machine accounts) or by DNS admins for specific named hosts, not as wildcards.

## Prerequisite
Needs a SACL auditing object creation on the DNS application partitions (DomainDnsZones and ForestDnsZones).

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "5137"
| EVAL cls = TO_LOWER(TO_STRING(winlog.event_data.ObjectClass)),
       dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       op_id = TO_STRING(winlog.event_data.OpCorrelationID)
| WHERE cls == "dnsnode" AND NOT ENDS_WITH(actor, "$")
  AND (STARTS_WITH(dn, "dc=*,") OR STARTS_WITH(dn, "dc=wpad,") OR STARTS_WITH(dn, "dc=isatap,"))
| KEEP @timestamp, host.name, actor, dn, op_id
```
`STARTS_WITH` matches literally, so `dc=*,` means a record actually named `*`.

## Suppression
Suppress by `op_id` for 1h. Alerts missing a key field are not suppressed. A different record always alerts.

## Known false positives / exclusions
- A DNS admin deliberately creating a WPAD record for a real proxy configuration. Confirm against change control.

## Triage
- Find the IP the record points to and the host behind it, and delete the record. Check that host for credential capture or relay activity, and DCs for NTLM authentications toward it (WE13).
- Consider restricting record creation in the zones to DNS admins, which removes the attack path.

## Test
In a lab, create a `wpad` record in an AD-integrated zone as a standard user.
