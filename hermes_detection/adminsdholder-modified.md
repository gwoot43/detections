# AdminSDHolder modified — the permission that SDProp copies back

`AdminSDHolder`'s permissions are copied onto **every protected account** (Domain Admins, Enterprise Admins, Administrators and the rest) by SDProp, roughly hourly. An entry added here grants rights over all of them at once, and it **returns** after being removed from any individual account — which is what makes it persistence rather than a one-off grant.

`rules/05-identity/I11` has the right object and the right `value added` operation. Two changes here: the **ACL write (`nTSecurityDescriptor`) is separated from other attribute writes** — the ACL is the abuse, and anything else on this object is a different conversation — and the **added ACE is carried as the finding**, with the trustee named, because that is what the analyst has to remove.

```esql
FROM logs-yourorg-microsoft-windows*
// One hour in the query: SDProp runs hourly, so the window matches the propagation cycle.
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code == "5136"
| EVAL dn = TO_LOWER(TO_STRING(winevt.event_data.object_dn)),
       attr = TO_LOWER(TO_STRING(winevt.event_data.attribute_ldap_display_name)),
       actor = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, user.name, "")),
       optype = TO_LOWER(COALESCE(TO_STRING(winevt.event_data.operation_type), "")),
       val = TO_STRING(winevt.event_data.attribute_value),
       op_id = TO_STRING(winevt.event_data.op_correlation_id)
| WHERE dn LIKE "*cn=adminsdholder,cn=system,*"
// The paired "value deleted" event repeats the old value; only the addition grants anything.
  AND (optype == "value added" OR optype LIKE "*14674*")
// The ACL is the finding. A change to any other attribute on this object is unusual but is a different
// investigation, so it is labelled rather than mixed in.
| EVAL shape = CASE(attr == "ntsecuritydescriptor", "acl_changed", "other_attribute")
| STATS changes = COUNT(*),
        aces = MV_SLICE(VALUES(val), 0, 4),
        attributes = MV_SLICE(VALUES(attr), 0, 4),
        ops = MV_SLICE(VALUES(op_id), 0, 3),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY shape, actor, winlog.computer_name
| SORT changes DESC
| LIMIT 100
```

Deploy every 15 minutes over the last hour. Suppress by `actor` + `shape` for 24h.

## Reading the alert
- **`aces`** is the finding: the added access control entry, with the trustee SID and the granted right. `GenericAll`, `WriteDACL` or `WriteOwner` on AdminSDHolder is domain-wide control over every privileged account.
- **`actor`** is who wrote it. This object is essentially never touched after the domain is built, so any actor is worth a call; a non-Tier-0 account is a compromised one.
- **`shape = other_attribute`** is not the ACL abuse — an owner change, or a description edit by a script. Keep it visible, but do not page on it.
- **`first_seen`** matters: if the ACE was added and SDProp has already run, the same ACE is now on every protected account and removing it from AdminSDHolder alone is not enough.

## Nearest benign twins
- **Deliberate hardening by the AD team** — removing a stale ACE is a `value deleted` and does not appear here; *adding* one during a hardening review does. Ticketed, and the actor is a named engineer on a jump host.
- **A directory migration tool** re-creating inherited permissions. It writes `nTSecurityDescriptor` on many objects, not just this one — if it is only ever this object, it is not the migration tool.
- **Domain build or forest recovery**, where the object is set up once. Planned, and the actor is the build account.

## What it misses
- **The propagation itself.** SDProp copying the ACE onto protected accounts writes those accounts' own `nTSecurityDescriptor`, which is a different object — if you want to see the spread, watch 5136 on the protected accounts in the hour after this fires.
- **An ACE added to a protected account directly**, without touching AdminSDHolder — that is `I02` (Tier-0 group change) territory, and the reason both rules exist.
- **A DC without a SACL on the System container**, where no 5136 is produced at all. The probe settles it.

## Probe before enabling
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 30 days AND event.code == "5136"
| STATS events = COUNT(*), last = MAX(@timestamp) BY winevt.event_data.object_dn
| WHERE winevt.event_data.object_dn LIKE "*cn=system,*"
| SORT events DESC
| LIMIT 10
```
Empty means directory-object auditing is not covering the System container, and this rule is a dead letter regardless of tuning.

## Pipeline
DC and AD events come from `logs-yourorg-microsoft-windows*` - the only Windows source in this estate, for every
channel. Event data is under `winevt.event_data.*` in snake_case, and the event's own Computer field is
`winlog.computer_name`, **not** `host.name`: the two hold different values here, and `host.name` is the agent's
identity rather than the machine that logged the event. A key that does not exist returns null, so a renamed
field makes the rule match nothing instead of failing.

## References
- `rules/05-identity/I11-adminsdholder-modified.md` - the rule this refines
- `rules/05-identity/I02-tier0-group-change.md` - the direct-membership route to the same rights
- MITRE T1098 (account manipulation), T1222 (file and directory permissions modification)
