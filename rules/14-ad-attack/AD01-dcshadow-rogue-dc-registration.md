---
id: AD01
name: Rogue domain controller registration (DCShadow)
category: ad-attack
status: todo
severity: critical
rank: 1
language: esql
index: logs-windows.security-*
mitre: [T1207]
data_source: Windows Security events 5137 (object created) and 5136 (object modified) from domain controllers
suppression:
  fields: [op_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A domain controller exists in Active Directory as a server object and an NTDS Settings (`nTDSDSA`) object under the Sites container of the configuration partition, and its computer account carries the directory replication SPN (the DRS interface GUID `E3514235-4B06-11D1-AB04-00C04FC2DCD2`) and a `GC/` SPN. A rogue DC registration creates those objects or adds those SPNs to a computer that is not a real DC, so it can push changes into the directory through replication, bypassing the change auditing on normal writes. Real DC promotions are rare, planned events, so every hit is worth a call.

## Prerequisite
5137 needs a SACL on the configuration partition's Sites container auditing object creation. 5136 needs the usual directory-object auditing. Confirm both produce events before relying on this.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code IN ("5137", "5136")
| EVAL cls = TO_LOWER(TO_STRING(winlog.event_data.ObjectClass)),
       dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN)),
       attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       val = TO_LOWER(TO_STRING(winlog.event_data.AttributeValue)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       op_id = TO_STRING(winlog.event_data.OpCorrelationID)
| EVAL dc_object_created = event.code == "5137" AND cls IN ("ntdsdsa", "server") AND dn LIKE "*cn=sites,cn=configuration,*",
       drs_spn_added = event.code == "5136" AND attr == "serviceprincipalname"
                       AND (val LIKE "e3514235-4b06-11d1-ab04-00c04fc2dcd2/*" OR val LIKE "gc/*")
| WHERE dc_object_created OR drs_spn_added
// real DCs carry these SPNs; list your DC computer objects so only non-DC targets alert
| WHERE NOT (drs_spn_added AND dn LIKE "*ou=domain controllers,*")
| KEEP @timestamp, host.name, actor, cls, dn, attr, val, op_id, dc_object_created, drs_spn_added
```

## Suppression
Suppress by `op_id` for 1h. Alerts missing a key field are not suppressed. One registration writes several objects and attributes in one operation; a separate operation always alerts.

## Known false positives / exclusions
- A planned DC promotion or demotion creates the same objects. Confirm against change control; never exclude permanently.
- DCs moved outside the Domain Controllers OU need their OU added to the exclusion line.

## Triage
- Treat as active domain compromise. Identify the computer the objects or SPNs point to, isolate it, and review replication metadata (`repadmin /showobjmeta`) for objects changed around the alert time, since those changes bypassed normal event logging.
- The actor needed Domain Admin-equivalent rights; review how those were obtained (I02, I01, AD02).

## Test
Validate against the events written by a planned lab DC promotion.
