# Rogue domain controller registration (DCShadow)

A domain controller is three directory facts: a **server object** and an **NTDS Settings (`nTDSDSA`) object** under `CN=Sites,CN=Configuration`, and a computer account carrying the **DRS replication SPN** (`E3514235-4B06-11D1-AB04-00C04FC2DCD2/<DSA-GUID>/<domain>`) plus a `GC/` SPN. DCShadow registers those facts for a machine that is not a DC, then pushes changes through replication — which bypasses the change auditing that normal writes produce.

`rules/14-ad-attack/AD01` has the right two anchors. This version changes three things: the **target check is an entity list rather than a comment**, the `OperationType` test tolerates both spellings, and the actor is kept as a column so the alert names who registered it.

```esql
FROM logs-system.security*, logs-windows.forwarded*
// 15 minutes in the query: a rogue registration is a handful of events seconds apart.
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.code IN ("5137", "5136")
| EVAL cls = TO_LOWER(TO_STRING(winlog.event_data.ObjectClass)),
       dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN)),
       attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       val = TO_LOWER(TO_STRING(winlog.event_data.AttributeValue)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, user.name, "")),
       optype = TO_LOWER(COALESCE(TO_STRING(winlog.event_data.OperationType), ""))
// The two shapes. Object creation is unambiguous; the SPN add is the same fact attached to an existing computer.
| EVAL dc_object_created = event.code == "5137" AND cls IN ("ntdsdsa", "server")
                          AND dn LIKE "*cn=sites,cn=configuration,*",
       drs_spn_added = event.code == "5136" AND attr == "serviceprincipalname"
// "value added" is the only operation that grants the right; the paired deletion repeats the old value.
                       AND (optype IN ("value added") OR optype LIKE "*14674*")
                       AND (val LIKE "e3514235-4b06-11d1-ab04-00c04fc2dcd2/*" OR val LIKE "gc/*")
| WHERE dc_object_created OR drs_spn_added
// The real DCs carry these SPNs by definition - an entity list, not a name pattern, because every hit on a
// genuine DC is noise and a renamed attacker machine defeats a pattern in the other direction.
| WHERE NOT (actor IN ("<dc01>$", "<dc02>$") OR dn LIKE "*cn=<dc01>,*" OR dn LIKE "*cn=<dc02>,*")
| STATS events = COUNT(*),
        kinds = MV_SLICE(VALUES(CASE(dc_object_created, "dc_object_created", "drs_spn_added")), 0, 3),
        objects = MV_SLICE(VALUES(dn), 0, 5),
        values = MV_SLICE(VALUES(val), 0, 4),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY actor, winlog.computer_name
| SORT events DESC
| LIMIT 100
```

Deploy every 5 minutes over the last 15. Suppress by `actor` for 24h.

## Reading the alert
- **`objects`** should contain `cn=sites,cn=configuration` for the object-creation shape: that is the rogue DC's NTDS Settings entry. Anything outside the configuration partition is a different story.
- **`values`** on the SPN shape is the DRS GUID followed by the DSA GUID and domain. The DSA GUID is the rogue DC's own identity — search the directory for it afterwards; the machine will still hold it.
- **`actor`** is who pushed the registration. DCShadow normally runs as a compromised Tier-0 account from a machine that is not a DC, so the actor's recent logons name the host to isolate.
- **`kinds`** tells you whether the rogue was registered from scratch (`dc_object_created`) or bolted onto an existing computer account (`drs_spn_added`).

## Nearest benign twins
- **A genuine DC promotion.** Planned, ticketed, and the actor is the admin running `Install-ADDSDomainController` from the new DC itself, with `*$`-style machine identity alongside. The entity list above already covers the incumbent DCs; record a promotion window rather than the event code.
- **A DC rebuild or restore** does the same writes. Same answer: the change register, and the actor being on the new host.
- **Directory synchronisation products** writing to the configuration partition. Rare; they do not add the DRS SPN, which is why the SPN test is the sharper of the two shapes.

## What it misses
- **DCShadow fully performed**, where the registration is later cleaned up: the cleanup is a 5136/5138-style deletion, and this rule only keeps the additions — deliberately, since the removal is what an attacker does last.
- **Replication being pushed from a genuinely registered but compromised DC** — nothing here can distinguish that; `AD02` (who holds replication rights) and `I01`/`dcsync-with-origin` are the neighbours.
- **A host where DS Change auditing is off**: no 5136/5137 at all. The probe below settles it.

## Probe before enabling
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE @timestamp >= NOW() - 30 days AND event.code IN ("5136", "5137")
| STATS events = COUNT(*), last = MAX(@timestamp) BY event.code, winlog.channel
| SORT events DESC
```
5137 requires a SACL on the Sites container auditing object creation, and 5136 the usual directory-object auditing. If 5137 returns nothing at all, only the SPN shape is live — say so in the rule description rather than shipping a branch that cannot fire.

## References
- `rules/14-ad-attack/AD01-dcshadow-rogue-dc-registration.md` - the rule this refines
- MITRE T1207 (rogue domain controller)
- Microsoft, [MS-ADTS] NTDS Settings objects and the `E3514235-4B06-11D1-AB04-00C04FC2DCD2` DRS interface GUID
