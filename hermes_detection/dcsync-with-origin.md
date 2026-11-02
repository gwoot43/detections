# DCSync with its origin — replication GUID plus the logon address

`rules/05-identity/I01` already owns the anchor: **4662 whose `Properties` names a replication right**. That is the only thing DCSync cannot avoid, because `DS-Replication-Get-Changes-All` is the right that releases password hashes. This is the same detection with the two things I01 leaves to the analyst — the **third GUID**, and the **host the account authenticated from**, so triage does not start with a bare username.

Why the third GUID matters: `1131f6aa` (plain Get-Changes) is excluded from I01 on purpose, because DirSync-based audit products use it constantly and it releases no secrets. Kept as its own column here instead of as a filter, so a run that requests only base replication is still visible without turning the rule into a DirSync alert.

```esql
FROM logs-yourorg-microsoft-windows*
// 15 minutes in the query: one DCSync run emits many 4662 rows, and the enrichment below needs a window.
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.code IN ("4662", "4624")
| EVAL subject = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, user.name, "")),
       props = TO_LOWER(TO_STRING(winevt.event_data.properties)),
// The three replication rights. Get-Changes alone is routine directory sync and releases nothing; the pair
// with Get-Changes-All is what dumps hashes. Counted separately rather than filtered, so a base-replication
// only run still produces a row.
       all_changes = props LIKE "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*",
       filtered = props LIKE "*89e95b76-444d-4c62-991a-0facbeda640c*",
       base_changes = props LIKE "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*",
       repl = event.code == "4662" AND (all_changes OR filtered OR base_changes),
// 4624 type 3 = a network logon, which is where the requesting account's address is recorded. 4662 never has one.
       net_logon = event.code == "4624" AND TO_STRING(winevt.event_data.logon_type) == "3"
// Machine accounts replicate by design: every DC, and gMSAs such as Entra Cloud Sync's.
| WHERE NOT subject LIKE "*$"
| STATS replications = COUNT(*) WHERE repl,
        secret_reads = COUNT(*) WHERE all_changes OR filtered,
        objects = COUNT_DISTINCT(winevt.event_data.object_name, 4000) WHERE repl,
        dcs = COUNT_DISTINCT(winlog.computer_name),
        masks = MV_SLICE(VALUES(winevt.event_data.access_mask), 0, 3),
        logon_ips = MV_SLICE(VALUES(CASE(net_logon, winevt.event_data.ip_address, NULL)), 0, 6),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY subject
// Any replication by a user account is the event - the floor of 1 is deliberate, not a tuned number. secret_reads
// separates "dumped hashes" from "directory sync", and logon_ips is the thing I01 made the analyst go and find.
// The 30-day probe at the foot of this file is the baseline that will show whether 1 is too low in this estate.
| WHERE replications >= 1
| SORT secret_reads DESC, replications DESC
| LIMIT 100
```

Deploy every 5 minutes over the last 15. Suppress by `subject` for 1h.

## Reading the alert
- **`secret_reads`** above zero means `Get-Changes-All` or the filtered set was used - hashes left the directory. This is a domain-compromise event, not a suspicious one.
- **`logon_ips`** is the answer to "from where". A DC's own address is expected only for a DC; anything else is the host to isolate first. On an empty list the account used a logon session this window did not capture - widen to 1h before concluding.
- **`objects`** is the scale: one object is a targeted `lsadump::dcsync /user:krbtgt`, hundreds is a full sync.
- **`masks`** shows the access mask on the rows. Your pipeline writes no `0x100` for security-descriptor reads, so do not gate on it - but if it appears here it confirms control-access semantics on the replication rights.

## Nearest benign twins
- **The Entra Connect sync account** (`MSOL_<hex>`, or whatever yours is called). Machine-account gMSAs are already excluded by the `*$` filter; a named sync account is not, so keep it as an **entity pair** rather than a name pattern, and let first-seen do the rest.
- **DirSync-based audit and password-sync products** that legitimately hold `Get-Changes`. They show `secret_reads` only if they were granted `Get-Changes-All`, which is worth knowing independently.
- **A migration or consolidation project** using ADMT-style tooling. Rare, ticketed, and an entity pair for the project's window.

## What it misses
- **DCSync run with a stolen machine account** - excluded by the `$` filter by design, and the reason `AD02` (who was granted replication rights) and `WE09` (NTDS access) exist.
- **DCShadow**, which registers a rogue DC rather than replicating - `AD01`.
- **Replication over DRSUAPI from an unmanaged host** when the DC's auditing is off: nothing to see here at all. That is a network rule (RPC to 445/135 plus the DC's DRS bind), and it needs a source you may not collect.
- **The domain NC vs a single object**: both are DCSync and both land here.

## Probe before trusting it
I01 carries the same prerequisite and this one inherits it: the 4662 replication rows must actually be written.
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 30 days AND event.code == "4662"
| STATS events = COUNT(*), last = MAX(@timestamp)
    BY winevt.event_data.subject_user_name, winevt.event_data.access_mask
| SORT events DESC
| LIMIT 30
```
If the top rows are machine accounts and a sync account carrying a mask, the audit is live. If no row carries a replication GUID, DCSync is unobservable from this log and the detection has to move to the network side.

## Pipeline
DC and AD events come from `logs-yourorg-microsoft-windows*` - the only Windows source in this estate, for every
channel. Event data is under `winevt.event_data.*` in snake_case, and the event's own Computer field is
`winlog.computer_name`, **not** `host.name`: the two hold different values here, and `host.name` is the agent's
identity rather than the machine that logged the event. A key that does not exist returns null, so a renamed
field makes the rule match nothing instead of failing.

## References
- `rules/05-identity/I01-dcsync.md` - the canonical rule this extends; same anchor, plus origin and the third GUID
- `rules/14-ad-attack/AD02-replication-rights-granted.md` - the step before this one, and the answer when the actor is a machine account
- MITRE T1003.006 (DCSync), T1222 (modify permissions)
- Microsoft, [MS-DRSR] and the `DS-Replication-Get-Changes*` control-access rights
