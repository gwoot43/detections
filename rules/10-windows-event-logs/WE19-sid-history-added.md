---
id: WE19
name: SID History added to an account
category: windows-event-logs
status: todo
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1078.002, T1134.005]
data_source: CrowdStrike FDR / Windows Security events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
> **Not deployable on `4765`/`4766` in this estate** - those events are not collected. The remaining event path is
> **`5136`** with `AttributeLDAPDisplayName = sIDHistory`, which needs DS Change auditing over the user objects;
> the query below is that version. If `5136` is also absent, SID History is not observable from event logs at all
> and the compensating control at the foot of this file - a scheduled directory diff - is the only coverage.


`sIDHistory` lets an account carry **additional SIDs** that the domain still honours for authorisation. Written
legitimately it is a migration tool: ADMT stamps the old domain's SID onto the migrated account so file and folder
ACLs from the source domain keep working. Written by an attacker it is the quietest privilege escalation in AD —
no group membership, no ACL change on any object, just a SID on the account that already holds the rights.

The record used here is **`5136`** with `AttributeLDAPDisplayName = sIDHistory` — the write as seen on the user
object. It needs **DS Change auditing** over the user objects, which is the same switch that enables DCShadow,
AdminSDHolder and RBCD detection, so it is worth having on for more than this rule.

`4765`/`4766` are the account-management view of the same act and are the cleaner source, but they are not
collected here. If they are ever enabled, they are the version to prefer: one event per change instead of one per
attribute, and no SACL dependency.

The discriminator is the **RID of the SID being added**, because that is what decides what the account becomes.
`-500` is the built-in Administrator, `-512` Domain Admins, `-519` Enterprise Admins, `-518` Schema Admins,
`-516` Domain Controllers, `-502` `krbtgt`, `-520` Group Policy Creator Owners, `-544` BUILTIN\Administrators.
A SID history write that adds any of those is not a migration.

```esql
FROM logs-yourorg-microsoft-windows*
// One hour in the query: a SID History write is rare enough that a single event is the finding.
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code == "5136"
| EVAL attr = TO_LOWER(COALESCE(winevt.event_data.attribute_ldap_display_name, "")),
       actor = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, user.name, "")),
       dn = TO_LOWER(TO_STRING(COALESCE(winevt.event_data.object_dn, ""))),
       val = TO_UPPER(TO_STRING(COALESCE(winevt.event_data.attribute_value, ""))),
       optype = TO_LOWER(COALESCE(TO_STRING(winevt.event_data.operation_type), ""))
// The attribute, and only the addition: the paired "value deleted" event is the clean-up, not the act.
| WHERE attr == "sidhistory" AND (optype == "value added" OR optype LIKE "*14674*")
// The RID decides what the account becomes. RLIKE is Lucene: no "$" anchor, the whole string is matched
// implicitly, and the RID must be followed by a non-digit or the end - so -512 matches and -5121 does not.
| EVAL privileged = val RLIKE """.*-(500|502|512|516|518|519|520|521|544)([^0-9].*)?""",
       finding = CASE(privileged, "privileged_sid_added", "sid_history_added")
| STATS events = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        objects = MV_SLICE(VALUES(dn), 0, 4),
        sids = MV_SLICE(VALUES(val), 0, 4),
        dcs = COUNT_DISTINCT(winlog.computer_name)
    BY finding, actor
// No threshold: a SID History write outside a migration window is the finding. The suppression is the control.
| SORT first_seen ASC
| LIMIT 100
```

Deploy every 15 minutes over the last hour. Suppress by `actor` + `objects` for 24h.

## Reading the alert
- **`finding = privileged_sid_added`** is domain compromise in progress: the target account now carries
  Administrator or Domain Admin rights that no group membership shows. Disable the account first, then remove the
  SID history, then look for what it authenticated against.
- **`sids`** is the added SID itself, taken from the attribute value. Compare its domain prefix against the target account's domain: a **different**
  domain means cross-domain migration or trust abuse, the same domain means someone stamped a local privileged RID.
- **`finding = sid_history_attempt_failed`** is not noise — it is an attempt that failed on permissions or on a
  protected account, and it usually precedes a retry with more rights.
- **`objects`** names the account that gained the SIDs (the user object's DN). A **machine account** (`…$`) is unusual and worth its own
  escalation: computers do not migrate this way in a normal build.
- **`objects` empty** means the pipeline did not render `object_dn`; the SID in `sids` is then the only
  identifier you have, and it names the account that gained the privilege.

## Nearest benign twins
- **An ADMT migration**, which is the whole reason the field exists. It runs as a named service account, in a
  ticketed window, and stamps SIDs onto many accounts at once. Entity pair: migration account + the source domain
  SID prefix. Never suppress the event code.
- **A domain consolidation project** merging several source domains. Same shape, larger volume, and it lasts weeks —
  which is exactly why the exclusion has to be time-bounded rather than permanent.
- **A forest recovery** that re-creates accounts with their original SIDs. Rare, planned, and it comes from the
  recovery account on a single DC.

## What it misses
- **A SID History write with DS Change auditing off**, or on objects outside the SACL: nothing is written, and
  `4765`/`4766` are not collected here either, so there is no second path.
- **The account-management view**: `4765`/`4766` would be the cleaner source if it were enabled - one event per
  change, no SACL dependency - and would also catch a write this SACL does not cover.
- **The use of the SID.** This rule sees the write; the payoff is the account authenticating with it — `4672` for
  special privileges, `4624` for the logon, or an access to a resource whose ACL names the source domain. Those
  are separate detections, and they are the corroboration to chase by hand.
- **`sIDHistory` removed** afterwards, which is a `5136` value-deleted event — the clean-up, not the act.
- **A migration tool writing through a replication path** rather than LDAP/SAMR, which may produce neither event.

## Probe before enabling
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 90 days
  AND event.code == "5136"
| STATS events = COUNT(*), last = MAX(@timestamp),
        sidhistory = COUNT(*) WHERE TO_LOWER(winevt.event_data.attribute_ldap_display_name) LIKE "*sidhistory*"
    BY winlog.computer_name
```
No rows means DS Change auditing is not covering directory objects at all - which also takes DCShadow,
AdminSDHolder and RBCD detection with it, so the gap is bigger than this rule. Rows but `sidhistory` at zero means
the attribute is not being written by any audited change: check the SACL covers user objects, and confirm the field
name against a real change.

## Compensating control: the directory diff

`sIDHistory` is **enumerable**, which is the one thing that makes this recoverable without any audit policy. Run a
daily export and alert on new rows - it catches every write, including ones no SACL covers:

```powershell
Get-ADUser -LDAPFilter '(sIDHistory=*)' -Properties sIDHistory |
  Select-Object SamAccountName, DistinguishedName,
                @{n='SidHistory';e={$_.sIDHistory -join ';'}},
                @{n='Collected';e={Get-Date -Format o}} |
  Export-Csv -NoTypeInformation -Path C:\ProgramData\ad-inventory\sidhistory.csv
```
Ship that file to the index and alert on any `SamAccountName` that was not present the previous day - a new row is
a new SID History entry. It is a scheduled job rather than a detection, and it is the honest answer when the event
path is closed: the directory itself is the source of truth.

## References
- `rules/10-windows-event-logs/WE03-directory-defense-changes.md` - the combined trust/SID-History/DSRM rule; this is the dedicated version, classified by the added SID's RID
- `rules/10-windows-event-logs/WE03-trust-sidhistory-dsrm-by-actor.md` - the same events grouped by actor, for estates that want one rule for all three
- `docs/AD-ATTACK-REFERENCE.md` - the AD-team reference: what each technique gets and the fields it needs
- MITRE T1134.005 (SID-History injection), T1078.002 (domain accounts)
