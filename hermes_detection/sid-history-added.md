# SID History added to an account

`sIDHistory` lets an account carry **additional SIDs** that the domain still honours for authorisation. Written
legitimately it is a migration tool: ADMT stamps the old domain's SID onto the migrated account so file and folder
ACLs from the source domain keep working. Written by an attacker it is the quietest privilege escalation in AD —
no group membership, no ACL change on any object, just a SID on the account that already holds the rights.

The record is **`4765`** — SID History was added to an account — with **`4766`** for a failed attempt, which still
counts because it usually precedes a retry with more rights. Both are audited under **Account Management**, which
this estate already has on for the account-reset rules, so nothing new has to be enabled.

(`5136` with `AttributeLDAPDisplayName = sIDHistory` is the same write seen on the object, and it is deliberately
**not** used here: it needs DS Change auditing over the objects, it produces one event per attribute change, and
it would only add a second path to the same finding.)

The discriminator is the **RID of the SID being added**, because that is what decides what the account becomes.
`-500` is the built-in Administrator, `-512` Domain Admins, `-519` Enterprise Admins, `-518` Schema Admins,
`-516` Domain Controllers, `-502` `krbtgt`, `-520` Group Policy Creator Owners, `-544` BUILTIN\Administrators.
A SID history write that adds any of those is not a migration.

```esql
FROM logs-yourorg-microsoft-windows*
// One hour in the query: 4765 is rare enough that a single event is the finding, and the window keeps the
// grouping honest across a migration batch.
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code IN ("4765", "4766")
| EVAL actor = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, user.name, "")),
       target = TO_LOWER(COALESCE(winevt.event_data.target_user_name, "")),
// 4765 and 4766 carry the added SID in their own field.
       added = TO_UPPER(TO_STRING(COALESCE(winevt.event_data.sid_history, "")))
// The RID decides what the account becomes. RLIKE is Lucene: no "$" anchor, the whole string is matched
// implicitly, and the RID must be followed by a non-digit or the end - so -512 matches and -5121 does not.
| EVAL privileged = added RLIKE """.*-(500|502|512|516|518|519|520|521|544)(\\D.*)?""",
       finding = CASE(event.code == "4766", "sid_history_attempt_failed",
                       privileged, "privileged_sid_added",
                       "sid_history_added")
| STATS events = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        targets = MV_SLICE(VALUES(target), 0, 4),
        sids = MV_SLICE(VALUES(added), 0, 4),
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
- **`targets` empty** means the pipeline did not render `target_user_name`; the SID in `sids` is then the only
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
- **A SID History write where account-management auditing is off**: nothing is written at all. There is no second
  path in this rule by design - if `4765` is not produced, the field is unobservable from this source.
- **The use of the SID.** This rule sees the write; the payoff is the account authenticating with it — `4672` for
  special privileges, `4624` for the logon, or an access to a resource whose ACL names the source domain. Those
  are separate detections, and they are the corroboration to chase by hand.
- **`sIDHistory` removed** afterwards, which is a `5136` value-deleted event — the clean-up, not the act.
- **A migration tool writing through a replication path** rather than LDAP/SAMR, which may produce neither event.

## Probe before enabling
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 90 days
  AND event.code IN ("4765", "4766")
| STATS events = COUNT(*), last = MAX(@timestamp),
        with_sid_field = COUNT(*) WHERE winevt.event_data.sid_history IS NOT NULL
    BY winlog.computer_name
```
No rows means account-management auditing is not recording SID History, and the rule has no other source. Rows
with `with_sid_field` at zero mean the event arrives but the field name is not the one this query expects - probe
`winevt.event_data.sid_history` against a real change before deploying.

## References
- `rules/10-windows-event-logs/WE03-directory-defense-changes.md` - the combined trust/SID-History/DSRM rule; this is the dedicated version, classified by the added SID's RID
- `hermes_detection/trust-sidhistory-dsrm-by-actor.md` - the same events grouped by actor, for estates that want one rule for all three
- `docs/AD-ATTACK-REFERENCE.md` - the AD-team reference: what each technique gets and the fields it needs
- MITRE T1134.005 (SID-History injection), T1078.002 (domain accounts)
