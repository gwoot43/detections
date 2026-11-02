# Tier-0 group membership granted — including the primaryGroupID route that produces no membership event

Adding an account to **Domain Admins** is the payoff step: one write converts a foothold into domain control. The membership is visible as **4728** (global group), but three things routinely defeat a 4728-only rule, and the second one produces *no membership event at all*:

- **Wrong group type.** The built-in **Administrators** group on a DC is local (**4732**), and **Enterprise Admins** / **Schema Admins** are universal (**4756**). Domain Admins alone is 4728.
- **`primaryGroupID = 512`.** Pointing a user's primary group at Domain Admins makes them a member without touching the group's `member` attribute. No 4728, no member write — the trace is a **4738** (user account changed) carrying the new primary group, and a **4662** property write when it is done over LDAP.
- **Case.** `LIKE` is case-sensitive, so a pipeline that lowercases SIDs makes `S-1-5-21-…-512` match nothing and the rule returns zero rows with no error. SIDs are compared upper-case here for that reason.

Matching on the **SID** rather than the group name is still right: a renamed, localised or lookalike group cannot defeat `-512`.

```esql
FROM logs-yourorg-microsoft-windows*
// 15 minutes in the query: a grant is a single write, and the corroborating events follow within seconds.
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.code IN ("4728", "4732", "4756", "4738", "4662")
| EVAL group_sid = TO_UPPER(TO_STRING(COALESCE(winevt.event_data.target_sid, winevt.event_data.group_sid, ""))),
       member = TO_LOWER(TO_STRING(COALESCE(winevt.event_data.member_name, winevt.event_data.target_user_name, ""))),
       actor = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, user.name, "")),
       pgid = TO_STRING(COALESCE(winevt.event_data.primary_group_id, winevt.event_data.new_primary_group_id, "")),
// 4662 carries the attribute being written; some pipelines render it as the schemaIDGUID, some as the
// LDAP display name, so both forms are matched and the probe below tells you which one you have.
       props = TO_LOWER(TO_STRING(winevt.event_data.properties))
// The five groups worth alerting on, by RID.
| EVAL tier0 = CASE(group_sid LIKE "S-1-5-21-*-512", "domain_admins",
                    group_sid LIKE "S-1-5-21-*-519", "enterprise_admins",
                    group_sid LIKE "S-1-5-21-*-518", "schema_admins",
                    group_sid LIKE "S-1-5-21-*-516", "domain_controllers",
                    group_sid LIKE "S-1-5-21-*-520", "gpo_creators",
                    ""),
// 4738 has no group SID: the privilege comes from the user's primary group being pointed at 512.
       primary_group = event.code == "4738" AND pgid == "512",
// 4662 is the same write seen on the object instead of the group - the LDAP path, and the only trace when
// the change is made without an account-management event.
       ldap_write = event.code == "4662" AND props LIKE "*primarygroupid*"
| WHERE tier0 != "" OR primary_group OR ldap_write
| EVAL shape = CASE(primary_group OR ldap_write, "primary_group_id_512", "member_added")
| STATS events = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        members = MV_SLICE(VALUES(member), 0, 5),
        groups = MV_SLICE(VALUES(group_sid), 0, 3),
        objects = MV_SLICE(VALUES(winevt.event_data.object_name), 0, 3),
        dcs = COUNT_DISTINCT(winlog.computer_name)
    BY shape, tier0, actor
| SORT first_seen ASC
| LIMIT 100
```

Deploy every 5 minutes over the last 15. Suppress by `actor` + `members` for 24h.

## Reading the alert
- **`shape = primary_group_id_512`** is the important row: it is the route that every membership-based rule misses, and the only way to see it is the 4738/4662 pair above. Treat it as a deliberate evasion rather than a misconfiguration.
- **`members`** names who was granted the rights. A **machine account** (`…$`) here is impersonation of a computer, not administration, and is worth its own escalation.
- **`tier0`** decides severity: `domain_admins` and `enterprise_admins` are domain/forest control; `gpo_creators` is quieter but enough to push a policy to every host.
- **`objects`** on a `primary_group_id_512` row is the user object that was changed - the account to disable first.
- **`dcs`** above one means the write replicated and was audited on more than one DC; that is normal for a single change seen twice, so read `events` before assuming repetition.

## Nearest benign twins
- **Onboarding by a PAM/IGA product**, which adds to privileged groups through a service account on a schedule. It is the common case, and it is why the actor - not the group - is the discriminator. Entity pair: `actor` + the PAM host.
- **A helpdesk adding someone to Administrators on a workstation** - that is a local group on a member server, and this rule only looks at `-512`/`-519`/`-518`/`-516`/`-520` RIDs, so it does not fire.
- **Migration projects** moving groups between domains, which add members in bulk. Ticketed, and the actor is the migration account.
- **`primaryGroupID` changes by an IGA tool** that manages primary groups as a matter of policy. Rare, but it exists: if you see it, verify the value is 512 and the target is a human, then entity-pair the tool.

## What it misses
- **Nested membership**: adding an account to a group that is *itself* a member of Domain Admins produces one 4728, on the other group's SID. Covering it needs a membership lookup, not a threshold - the honest answer is that a rule on RIDs cannot see it.
- **SID History injection** of a privileged SID, which is `4765/4766` and belongs with `trust-sidhistory-dsrm-by-actor`.
- **A direct ACL grant** instead of membership: `GenericAll` on the domain object, DCSync rights (`AD02`), or an ACE on `AdminSDHolder` (`adminsdholder-modified`). Attackers increasingly prefer these precisely because membership rules are common.
- **`4732` on a DC for the built-in Administrators group** is included, but the same event on a member server is not - scope by the event's computer name if you want both.
- **Audit Account Management being off** on the DCs, which produces no 4728/4732/4756 at all.

## Probe before enabling
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 30 days
  AND event.code IN ("4728", "4732", "4756", "4738", "4662")
| STATS events = COUNT(*), last = MAX(@timestamp) BY event.code
| SORT events DESC
```
No 4728 rows at all means Account Management auditing is off or the DCs are not in this index - fix that before tuning. Then confirm the SID casing and field name, which is the failure that looks like "caught nothing":

```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 30 days AND event.code == "4728"
| STATS events = COUNT(*) BY winevt.event_data.target_sid
| SORT events DESC
| LIMIT 10
```
Lowercase SIDs, or an empty `target_sid` column, are what a 4728-only rule silently dies on. Finally, for the `4662` branch, print what the pipeline actually puts in `properties` on a user object before trusting the `primarygroupid` match.

## Pipeline
DC and AD events come from `logs-yourorg-microsoft-windows*` - the only Windows source in this estate, for every
channel. Event data is under `winevt.event_data.*` in snake_case, and the event's own Computer field is
`winlog.computer_name`, **not** `host.name`: the two hold different values here, and `host.name` is the agent's
identity rather than the machine that logged the event. A key that does not exist returns null, so a renamed
field makes the rule match nothing instead of failing.

## References
- `certipy_detections/11-user-added-to-domain-admins.md` - the earlier 4728-only rule; this covers the group types and the primaryGroupID route it cannot see
- `rules/05-identity/I02-tier0-group-change.md` - the catalogue's Tier-0 group rule
- `adminsdholder-modified.md` - the ACL route to the same rights
- MITRE T1098.007 (additional local or domain groups), T1098 (account manipulation), T1078.002 (domain accounts)
