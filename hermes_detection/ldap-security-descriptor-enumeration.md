# AD ACL / security-descriptor enumeration (4662)

BloodHound-class collection ends by asking the directory for the **security descriptor** of many objects, because the DACL is the attack graph: every ACE is a possible `GenericAll`, `WriteDACL`, `WriteOwner`, `ForceChangePassword` or RBCD edge. Clients request it with the `LDAP_SERVER_SD_FLAGS_OID` control (OWNER 0x1, GROUP 0x2, DACL 0x4, SACL 0x8) and skip the SACL - **SharpHound asks 0x4/0x5, SoaPy and SOAPHound ask 0x7** - so the family is "owner/group/DACL without SACL", which is what Schwartz's BloodHound-family rule keys on. The precise server-side signal is Directory Service **1644** with `SDFlags:`, but **we do not collect 1644**: it only fires when NTDS diagnostics are raised to Level 5, and that is 10-50k EPS on a busy DC. What we do collect is **4662** (I01, AD04 and AD09 already depend on it), so the rule below works from that: one account touching **many distinct directory objects** through read-property or control-access. Caveat first - 4662 only records this if the object's SACL audits that access, so run the probe before trusting it, and if SD reads never appear, the LDAP half of collection is visible only on the network side (**24**). The threshold is a starting value; suppress by the subject account for 6h.

```esql
FROM logs-yourorg-microsoft-windows*
// 4662 = an operation on a SACL-audited AD object. 0x10 = read property, 0x100 = control access - the
// rights that cover reading an object's security descriptor. (winlog.event_data.* if you run the
// Elastic integration rather than this pipeline.)
| WHERE event.code == "4662"
  AND winevt.event_data.access_mask IN ("0x10", "0x100")
// The replication rights are DCSync - that is I01's rule. Leaving them in makes this fire on every DCSync.
  AND NOT (winevt.event_data.properties LIKE "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
        OR winevt.event_data.properties LIKE "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
        OR winevt.event_data.properties LIKE "*89e95b76-444d-4c62-991a-0facbeda640c*")
// DCs, backup products and Entra Connect read these by design, and they run as machine or sync accounts
  AND (user.name IS NULL OR NOT user.name LIKE "*$")
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user"))
// One row per account: how many different objects it looked at, and which properties it asked for.
| STATS objects = COUNT_DISTINCT(winevt.event_data.object_name, 4000),
        props = MV_SLICE(VALUES(winevt.event_data.properties), 0, 5),
        dcs = COUNT_DISTINCT(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 100 distinct objects in 15 minutes is a starting value - an admin checks a handful, a collector walks
// the directory. Measure your own p99 before tuning.
| WHERE objects >= 100
| SORT objects DESC
| LIMIT 100
```

Tell whether your estate logs SD reads at all before deploying - this lists the access-mask/object-type pairs 4662 actually carries for you:
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "4662"
| STATS n = COUNT(*) BY winevt.event_data.access_mask, winevt.event_data.object_type
| SORT n DESC
| LIMIT 25
```
If `0x10` / `nTSecurityDescriptor` never appears there while you know a tool read ACLs, that SACL is not set: no DC-side rule will see the read, and 24 (FDR fan-out across DCs) is the only view left.

## References

- Schwartz, *From Code to Coverage - A Detection Engineer's Journey Through the LDAP Wilderness* (TROOPERS26) - SDFlags 0x4/0x5 for SharpHound and 0x7 for SoaPy/SOAPHound, the 1644 Level-5 prerequisite and its EPS cost, `SDFlags`-based Sigma rule for the BloodHound family, the ADWS `[::1]` attribution problem: `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
- Huntress, *LDAP & Active Directory detection* parts 3-5 - `SDFlags` inside 1644, SharpHound group enumeration at `SDFlags: 0x5`: `huntress.com/blog/ldap-active-directory-detection-part-three`
- Microsoft, `LDAP_SERVER_SD_FLAGS_OID` - OWNER 0x1, GROUP 0x2, DACL 0x4, SACL 0x8: `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0`
- Microsoft, event 4662 - object operation on a SACL-audited AD object: `learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662`
- Compass Security, *BloodHound Inner Workings* parts 1-3 - SAMR, GPOLocalGroup and the session APIs, with packet traces
