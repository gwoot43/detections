---
id: S26
name: Conditional Access policy disabled, weakened or excluded - the cloud twin of WE02
category: entra-signin-extended
status: todo
language: esql
index: logs-azure.auditlogs-*
mitre: [T1562.001, T1078.004]
data_source: Entra ID audit log (policy management)
suppression:
  fields: [user.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

`WE02` catches an audit policy being changed on a domain controller - the on-premise version of "can I blind you".
Conditional Access is the cloud equivalent: it is what enforces MFA, blocks legacy auth and restricts where a
session can come from. An attacker with `Conditional Access Administrator` does not need to break MFA; they disable
the policy that requires it, sign in, and put it back.

Three changes matter, and they are all in the audit log with the before and after attached: the policy being
**disabled**, an **exclusion** added for a user or group, and the policy being **deleted**. A fourth - a policy
changed so it no longer covers `All users` - is the same act with better manners.

## Query

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp >= NOW() - 24 hours
  AND azure.auditlogs.operation_name IN ("Update conditional access policy.", "Delete conditional access policy.")
| EVAL actor = TO_LOWER(COALESCE(TO_STRING(azure.auditlogs.properties.initiated_by.user.userPrincipalName), "")),
       policy = TO_LOWER(COALESCE(TO_STRING(MV_FIRST(azure.auditlogs.properties.target_resources.display_name)), "")),
       op = TO_LOWER(TO_STRING(azure.auditlogs.operation_name)),
       // the changed properties arrive as an array of old/new pairs; stringifying keeps them greppable
       changes = TO_LOWER(TO_STRING(azure.auditlogs.properties.modified_properties)),
       result = TO_LOWER(COALESCE(TO_STRING(azure.auditlogs.result), ""))
// disabled, excluded, or deleted - the three ways a policy stops applying
| WHERE op LIKE "*delete*" OR changes LIKE "*disabled*" OR changes LIKE "*exclude*"
     OR changes LIKE "*state*enabled*false*"
| STATS changes_seen = COUNT(*), policies = MV_SLICE(VALUES(policy), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        results = MV_SLICE(VALUES(result), 0, 3)
    BY actor
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **The order matters.** Disable, sign in, re-enable within an hour is a single narrative: join this rule's
  `first_seen` to `signinlogs` for the same actor and window, and look for the sign-in that happened while the
  policy was off. That sign-in is the actual event.
- **`exclude`** added for a named user, rather than a group, is the narrower and more suspicious edit - a group can
  be an operational convenience, one named account is a door.
- **`Delete`** is louder than `Update` and has no benign version outside a decommission.

## Nearest benign twins

- **Policy work by the identity team** - the same two or three actors, in business hours, in pairs (disable,
  change, re-enable). Allowlist the actor, never the policy.
- **A pilot or report-only policy** being flipped to enabled, which is the reverse direction and should not match.
  If your tenant logs the old and new value in an order this rule misreads, filter on the `new_value` being
  `disabled` rather than on the string appearing anywhere.
- **Break-glass exclusion** being added during an incident. Documented, and it is a real change to review, not
  noise to suppress.

## What it misses

- **A policy narrowed without the words `disabled` or `exclude`** - removing a condition (dropping a location rule,
  changing an app scope) leaves a policy that still says `enabled`. Comparing the full before/after per policy,
  once a day, is the only way to catch it, and that is a baseline job rather than an alert.
- **Changes made directly in Graph API by an app** - same as `S25`: the actor is a GUID.
- **Policies that never existed** - an attacker who only needs one sign-in may not touch Conditional Access at all.
  This rule catches the deliberate blinding, not the absence of coverage.

## Baseline

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp >= NOW() - 90 days
  AND azure.auditlogs.operation_name IN ("Update conditional access policy.", "Delete conditional access policy.")
| EVAL actor = TO_LOWER(COALESCE(TO_STRING(azure.auditlogs.properties.initiated_by.user.userPrincipalName), ""))
| STATS changes = COUNT(*), days = COUNT_DISTINCT(BUCKET(@timestamp, 1 day)) BY actor
| SORT changes DESC
| LIMIT 50
```

## Test

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp >= NOW() - 7 days
  AND azure.auditlogs.operation_name IN ("Update conditional access policy.", "Delete conditional access policy.",
                                         "Add conditional access policy.")
| STATS events = COUNT(*) BY azure.auditlogs.operation_name
| SORT events DESC
```

If this returns nothing, the audit log is not being collected for policy operations and neither this rule nor `S25`
can fire.
