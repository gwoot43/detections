# SID History added to an account

`sIDHistory` lets an account carry **additional SIDs** that the domain still honours for authorisation. Written
legitimately it is a migration tool: ADMT stamps the old domain's SID onto the migrated account so file and folder
ACLs from the source domain keep working. Written by an attacker it is the quietest privilege escalation in AD —
no group membership, no ACL change on any object, just a SID on the account that already holds the rights.

Two records exist, and they are the same act from different angles:

- **`4765`** — SID History was added to an account (success). **`4766`** — the attempt failed, which is still an
  attempt and belongs in the same rule.
- **`5136`** with `AttributeLDAPDisplayName = sIDHistory` — the write as seen on the object, available when DS
  Change auditing covers it, and the only view if account-management auditing is off.

The discriminator is the **RID of the SID being added**, because that is what decides what the account becomes.
`-500` is the built-in Administrator, `-512` Domain Admins, `-519` Enterprise Admins, `-518` Schema Admins,
`-516` Domain Controllers, `-502` `krbtgt`, `-520` Group Policy Creator Owners, `-544` BUILTIN\Administrators.
A SID history write that adds any of those is not a migration.

```esql
FROM logs-yourorg-microsoft-windows*
// One hour in the query: 4765 is rare enough that a single event is the finding, and the window keeps the
// grouping honest across a migration batch.
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code IN ("4765", "4766", "5136")
| EVAL actor = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, user.name, "")),
       target = TO_LOWER(COALESCE(winevt.event_data.target_user_name, "")),
// 4765/4766 carry the added SID in their own field; 5136 carries it as the attribute value.
       sid_hist = TO_UPPER(TO_STRING(COALESCE(winevt.event_data.sid_history, ""))),
       attr = TO_LOWER(COALESCE(winevt.event_data.attribute_ldap_display_name, "")),
       dn = TO_LOWER(TO_STRING(COALESCE(winevt.event_data.object_dn, ""))),
       val = TO_UPPER(TO_STRING(COALESCE(winevt.event_data.attribute_value, "")))
| WHERE event.code IN ("4765", "4766") OR (event.code == "5136" AND attr == "sidhistory")
| EVAL added = CASE(event.code IN ("4765", "4766"), sid_hist, val),
// The RID decides what the account becomes. Everything else is context.
// RLIKE is Lucene: no "$" anchor, and the whole string is matched implicitly. The RID has to be
// followed by a non-digit (or end of string), so -500 matches and -5001 does not.
       privileged = added RLIKE """.*-(500|502|512|516|518|519|520|521|544)(\D.*)?""",
       finding = CASE(event.code == "4766", "sid_history_attempt_failed",
                       privileged, "privileged_sid_added",
                       "sid_history_added")
| STATS events = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        targets = MV_SLICE(VALUES(target), 0, 4),
        sids = MV_SLICE(VALUES(added), 0, 4),
        objects = MV_SLICE(VALUES(dn), 0, 3),
        dcs = COUNT_DISTINCT(winlog.computer_name)
    BY finding, actor
// No threshold: a SID History write outside a migration window is the finding. The suppression is the control.
| SORT first_seen ASC
| LIMIT 100
```

Deploy every 15 minutes over the last hour. Suppress by `actor` + `targets` for 24h.

## Reading the alert
- **`finding = privileged_sid_added`** is domain compromise in progress: the target account now carries
  Administrator or Domain Admin rights that no group membership shows. Disable the account first, then remove the
  SID history, then look for what it authenticated against.
- **`sids`** is the added SID itself. Compare its domain prefix against the target account's domain: a **different**
  domain means cross-domain migration or trust abuse, the same domain means someone stamped a local privileged RID.
- **`finding = sid_history_attempt_failed`** is not noise — it is an attempt that failed on permissions or on a
  protected account, and it usually precedes a retry with more rights.
- **`targets`** names the account that gained the SIDs. A **machine account** (`…$`) is unusual and worth its own
  escalation: computers do not migrate this way in a normal build.
- **`objects`** only appears on the `5136` shape — the user object's DN, which is what you need if `target` was
  rendered empty by the pipeline.

## Nearest benign twins
- **An ADMT migration**, which is the whole reason the field exists. It runs as a named service account, in a
  ticketed window, and stamps SIDs onto many accounts at once. Entity pair: migration account + the source domain
  SID prefix. Never suppress the event code.
- **A domain consolidation project** merging several source domains. Same shape, larger volume, and it lasts weeks —
  which is exactly why the exclusion has to be time-bounded rather than permanent.
- **A forest recovery** that re-creates accounts with their original SIDs. Rare, planned, and it comes from the
  recovery account on a single DC.

## What it misses
- **A SID History write on an account where account-management auditing is off** and DS Change auditing is also
  off: nothing is written at all. The probe below is the only way to know which shape you have.
- **The use of the SID.** This rule sees the write; the payoff is the account authenticating with it — `4672` for
  special privileges, `4624` for the logon, or an access to a resource whose ACL names the source domain. Those
  are separate detections, and they are the corroboration to chase by hand.
- **`sIDHistory` removed** afterwards, which is a `5136` value-deleted event — the clean-up, not the act.
- **A migration tool writing through a replication path** rather than LDAP/SAMR, which may produce neither event.

## Probe before enabling
Both shapes, because either can be the only one present:
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 90 days
| STATS events = COUNT(*), last = MAX(@timestamp)
    BY event.code
| WHERE event.code IN ("4765", "4766", "5136")
```
`4765` with no rows means account-management auditing is not recording SID History; `5136` with no rows means DS
Change auditing does not cover the objects. If both are empty, the field is unobservable here and this rule is a
reference rather than a deployment.

Then confirm the field names, since the two shapes disagree:
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 90 days AND event.code == "4765"
| STATS events = COUNT(*), with_sid_field = COUNT(*) WHERE winevt.event_data.sid_history IS NOT NULL
    BY winevt.event_data.target_user_name
```

## References
- `rules/10-windows-event-logs/WE03-directory-defense-changes.md` - the combined trust/SID-History/DSRM rule; this is the dedicated version with the RID classification
- `hermes_detection/trust-sidhistory-dsrm-by-actor.md` - the same events grouped by actor, for estates that want one rule for all three
- `docs/AD-ATTACK-REFERENCE.md` - the AD-team reference: what each technique gets and the fields it needs
- MITRE T1134.005 (SID-History injection), T1078.002 (domain accounts)
