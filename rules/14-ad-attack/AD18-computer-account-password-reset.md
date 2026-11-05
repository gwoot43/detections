---
id: AD18
name: Computer account password reset — the silent half of computer-account takeover
category: ad-attack
status: todo
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1078.002, T1098, T1558]
data_source: CrowdStrike FDR / Windows Security events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
`AD05` catches a computer account being **created** (`ms-DS-MachineAccountQuota` abuse). It does not catch the cheaper move: reset the password of a computer account that already exists, then authenticate as that machine. That is a route to RBCD, to a silver ticket, and to impersonating any host that trusts the machine's authentication — including, in the worst case, a domain controller's own account.

**4724** is "an attempt was made to reset an account's password", performed by someone other than the account. A machine account's password is reset legitimately by very few things: `netdom resetpwd`, a rejoin, some backup/restore tooling, and the machine itself. Anything else is a takeover step.

```esql
FROM logs-yourorg-microsoft-windows*
// 15 minutes in the query. Machine resets are rare, so a short window is enough and keeps the fleet counts honest.
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.code == "4724"
| EVAL actor = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, "")),
       target = TO_LOWER(COALESCE(winevt.event_data.target_user_name, ""))
// The target is a machine account: that is what makes this different from AD10, which watches Tier-0 users.
| WHERE target LIKE "*$"
// Machine-to-machine is normal (a rejoin, a failover, a restore). A user account resetting a machine account
// password is the move; SYSTEM is how the sanctioned tooling usually appears.
  AND NOT actor LIKE "*$"
  AND actor NOT IN ("system", "local system", "nt authority\\system")
| STATS resets = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        actors = MV_SLICE(VALUES(winevt.event_data.subject_user_name), 0, 4),
        subjects = MV_SLICE(VALUES(winevt.event_data.subject_domain_name), 0, 3),
        dcs = COUNT_DISTINCT(winlog.computer_name)
    BY target
// Any single reset by a user account is worth a look, so no threshold here - the suppression is the control.
// If your estate has a sanctioned rejoin tool, exclude it as an entity pair (actor + target) rather than
// by actor name alone.
| SORT first_seen ASC
| LIMIT 100
```

Deploy every 5 minutes over the last 15. Suppress by `target` + `actors` for 24h.

## Reading the alert
- **`actors`** is the whole finding. A helpdesk account rejoining a laptop is one story; a service account with no documented reason is another; `administrator` resetting a DC's machine account is a domain-compromise step.
- **`target`** is the machine whose authentication the actor can now perform. If it is a server rather than a workstation, treat the actor as having that server's rights.
- **`dcs`** above 1 means the resets happened on several DCs - either a directory-wide sweep or a replication artefact. Worth reading the timestamps before anything else.

## Nearest benign twins
- **`netdom resetpwd` / rejoin after a secure-channel failure**, run by a helpdesk or by a deployment tool. It is the common case, and it is why the actor matters more than the count. Entity pair once confirmed.
- **Backup and restore products** restoring a machine account. Usually SYSTEM, which the filter already removes.
- **A migration or domain-consolidation project**, where machine accounts are reset en masse. A ticketed project window, and an exclusion scoped to it.

## What it misses
- **A reset by a machine account**, which the filter removes - `$`-to-`$` resets are how legitimate tooling appears and how a compromised DC would appear too.
- **The takeover that never resets the password**: an RBCD write (`msDS-AllowedToActOnBehalfOfOtherIdentity`), a silver ticket with a captured machine hash, or a KeyCredential added - `I14`, `I12` and `AD05` cover those paths.
- **Computer accounts changed through `Set-ADComputer`/LDAP rather than SAMR**, where the event may be 4738 (changed) instead of 4724. If your tooling does that, the same logic applies to 4738 with a machine target.

## Baseline
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 30 days AND event.code == "4724"
| EVAL actor = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, "")),
       target = TO_LOWER(COALESCE(winevt.event_data.target_user_name, ""))
| WHERE target LIKE "*$" AND NOT actor LIKE "*$"
| STATS resets = COUNT(*), targets = COUNT_DISTINCT(target) BY actor
| SORT resets DESC
| LIMIT 30
```
The actors at the top of this list are your sanctioned rejoin tooling - record them as entity pairs. Anything below the top few is the population this rule alerts on.

## Pipeline
DC and AD events come from `logs-yourorg-microsoft-windows*` - the only Windows source in this estate, for every
channel. Event data is under `winevt.event_data.*` in snake_case, and the event's own Computer field is
`winlog.computer_name`, **not** `host.name`: the two hold different values here, and `host.name` is the agent's
identity rather than the machine that logged the event. A key that does not exist returns null, so a renamed
field makes the rule match nothing instead of failing.

## References
- `rules/14-ad-attack/AD05-computer-account-impersonation.md` - the create half; this is the reset half
- `rules/14-ad-attack/AD10-tier0-password-reset-by-other.md` - the same event for privileged *user* accounts
- MITRE T1098 (account manipulation), T1078.002 (domain accounts), T1558 (steal or forge Kerberos tickets)
