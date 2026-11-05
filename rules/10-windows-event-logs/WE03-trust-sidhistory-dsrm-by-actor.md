---
id: WE03
name: Trust, SID History and DSRM changes — grouped by who did it
category: windows-event-logs
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1484.001, T1134.005, T1098]
data_source: Windows Security events 4706/4716 (trust created or changed), 4765/4766 (SID History added or attempted), 4794 (DSRM password set)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
`rules/10-windows-event-logs/WE03` owns these five events (4706/4716 trust created or modified, 4765/4766 SID History added or attempted, 4794 DSRM password set) and its own reasoning is right: each is a rare directory change with no routine business cause. Two things stop it being usable as an alert rather than a change-log.

**4716 is monthly noise.** The trusted domain's password is changed on a schedule, and the DC that owns the trust does it as its **machine account**. WE03 filters on event code only, so every trust in the estate produces a row every cycle with no attacker involved. Excluding machine actors for that one event removes the whole population without touching the other four.

**The rows carry no actor.** WE03 keeps `message` - the rendered event text, which is the largest column in the index - and the analyst reads the answer out of a sentence. Grouping by `kind` and `actor` makes the finding the grouping, so "who created a trust" is the first column instead of a paragraph.

```esql
FROM logs-yourorg-microsoft-windows*
// One hour, stated in the query: these are rare events and a short window keeps the counts readable.
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code IN ("4706", "4716", "4765", "4766", "4794")
| EVAL actor = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, user.name, "")),
       target = TO_LOWER(COALESCE(winevt.event_data.target_user_name, "")),
       trust = TO_LOWER(COALESCE(winevt.event_data.target_domain_name, "")),
       kind = CASE(event.code == "4706", "trust_created",
                   event.code == "4716", "trust_modified",
                   event.code IN ("4765", "4766"), "sid_history",
                   "dsrm_password")
// The trust's own password rotation runs as the DC's machine account on a schedule. Every other combination -
// a user account changing a trust, any SID History write, any DSRM reset - has no routine cause.
| WHERE NOT (kind == "trust_modified" AND actor LIKE "*$")
| STATS events = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        targets = MV_SLICE(VALUES(target), 0, 4),
        trusts = MV_SLICE(VALUES(trust), 0, 4),
        dcs = COUNT_DISTINCT(winlog.computer_name)
    BY kind, actor
| SORT events DESC
| LIMIT 100
```

Deploy every 15 minutes over the last hour. Suppress by `kind` + `actor` for 24h.

## Reading the alert
- **`kind`** decides the response, and the four are not equally bad. `sid_history` on an ordinary account is privilege injection and the account is compromised. `trust_created` widens access across a boundary and needs the directory team on the phone. `dsrm_password` is a local-admin path onto a DC, so treat it as a controller-compromise step. `trust_modified` by a user is the quiet one - it changes how an existing trust behaves rather than announcing a new one.
- **`actor`** is the finding. A domain admin during a merger is one story; a service account, or an account that has never touched the directory configuration, is another.
- **`targets`** on a `sid_history` row is the account that just inherited the SID's rights. On `dsrm_password` there is usually no target - the action is machine-scoped, which is itself worth noticing.
- **`trusts`** names the external or forest boundary involved, which is what you check against the change register.

## Nearest benign twins
- **A planned forest trust in a merger** - ticketed, and the only frequent benign `trust_created`. It arrives from one admin account on one pair of DCs; keep it as an entity pair, never as a blanket exclusion of the event code.
- **ADMT or a migration tool adding SID History**, which is legitimate *inside its migration window* and never outside it. Scope the exclusion to the window, not to the tool.
- **DC deployment and rebuild**, where DSRM is set once by the build account. If DSRM resets appear more than once per build, that is the signal.
- **A monitoring or audit product** that reads trust attributes. It reads; it does not write, so it does not appear here.

## What it misses
- **`4707` trust removed**, which WE03 drops deliberately - it reduces access rather than granting it, and the case where an attacker removes a trust is a destruction story that belongs with the log-clearing rules.
- **A trust created and used without further configuration** - the write is here, the use is Kerberos traffic to an external realm, which needs a network rule.
- **SID History written through a tool that produces 4766 without 4765**, where the attempt fails but the intent is the same. Both codes are included, so the attempt is captured, but the *reason* is only in the failure text.
- **`dsHeuristics` or anonymous-bind weakening**, which is a different class of directory change (an LDAP policy attribute write, seen as 5136 when DS Change auditing is on). Worth its own rule; not this one.

## Baseline
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 90 days
  AND event.code IN ("4706", "4716", "4765", "4766", "4794")
| EVAL actor = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, user.name, "")),
       kind = CASE(event.code == "4706", "trust_created", event.code == "4716", "trust_modified",
                   event.code IN ("4765", "4766"), "sid_history", "dsrm_password")
| STATS events = COUNT(*), last = MAX(@timestamp) BY kind, actor
| SORT events DESC
| LIMIT 40
```
Every actor on this list is a sanctioned one until proven otherwise - the point is to have the list before the first alert, so the first unusual actor stands out rather than being lost in a novelty discussion.

## Pipeline
DC and AD events come from `logs-yourorg-microsoft-windows*` - the only Windows source in this estate, for every
channel. Event data is under `winevt.event_data.*` in snake_case, and the event's own Computer field is
`winlog.computer_name`, **not** `host.name`: the two hold different values here, and `host.name` is the agent's
identity rather than the machine that logged the event. A key that does not exist returns null, so a renamed
field makes the rule match nothing instead of failing.

## References
- `rules/10-windows-event-logs/WE03-directory-defense-changes.md` - the rule this refines; same five events, actor-grouped, with the 4716 rotation noise removed
- MITRE T1484.001 (group policy / domain trust modification), T1134.005 (SID History injection), T1098 (account manipulation)
- Microsoft, 4706/4716/4765/4766/4794 event schemas
