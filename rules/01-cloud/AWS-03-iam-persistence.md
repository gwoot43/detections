---
id: AWS-03
name: AWS IAM persistence - access key or console password for another user, admin policy attached, role trust changed
category: cloud
status: todo
language: esql
index: logs-aws.cloudtrail-*
mitre: [T1098.001, T1098.003, T1136.003]
data_source: AWS CloudTrail management events, IAM (Elastic AWS integration)
suppression:
  fields: [aws.cloudtrail.user_identity.arn, finding]
  duration: 24h
  missing_fields: do_not_suppress
---

**Not collected in this estate yet.** CloudTrail is not ingested. Run the probe in `AWS-02` first.

An attacker with IAM write access makes their access durable in a handful of ways. Each is one CloudTrail event:

| `finding` | Event | Why it is persistence |
|---|---|---|
| `access_key_for_another_user` | `CreateAccessKey` where the target user is not the caller | a long-lived key the real owner does not know about |
| `console_password_for_another_user` | `CreateLoginProfile` / `UpdateLoginProfile` for someone else | console access for a user who never had it, or a reset password |
| `admin_policy_attached` | `Attach{User,Role,Group}Policy` with `AdministratorAccess` or `IAMFullAccess` | escalation to admin, which is item 5's AWS half |
| `wildcard_inline_policy` | `Put{User,Role,Group}Policy` granting `"Action":"*"` or `iam:*` | the same escalation, written inline where policy reviews miss it |
| `role_trust_changed` | `UpdateAssumeRolePolicy` | a role made assumable from an account or principal the attacker controls |
| `added_to_admin_group` | `AddUserToGroup` to a group named like admin | escalation by membership |
| `iam_user_created` | `CreateUser` | **risk grade.** Infrastructure-as-code creates users too |

Self-service calls (a user creating their own access key) are excluded by comparing the target user with the caller.

## Query

Run every 15 minutes with a 20-minute lookback.

```esql
FROM logs-aws.cloudtrail-* METADATA _id, _index, _version
| WHERE event.provider == "iam.amazonaws.com"
  AND event.outcome == "success"
  AND event.action IN ("CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "AttachUserPolicy",
                       "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
                       "UpdateAssumeRolePolicy", "AddUserToGroup", "CreateUser")
| EVAL params = COALESCE(TO_STRING(aws.cloudtrail.request_parameters), ""),
       caller = TO_LOWER(COALESCE(user.name, ""))
// request_parameters is rendered as text, e.g. {userName=alice, policyArn=arn:aws:iam::aws:policy/AdministratorAccess}
| GROK params """userName=(?<target_user>[^,}\s]+)"""
| GROK params """groupName=(?<target_group>[^,}\s]+)"""
| GROK params """(?<wildcard_action>Action\\?"?\s{0,4}[:=]\s{0,4}\[?\s{0,4}\\?"?(\*|iam:\*)\\?"?\s{0,4}[,}\]])"""
| EVAL target = TO_LOWER(COALESCE(target_user, "")),
       grp = TO_LOWER(COALESCE(target_group, ""))
| EVAL finding = CASE(
         event.action == "CreateAccessKey" AND target != "" AND target != caller, "access_key_for_another_user",
         event.action IN ("CreateLoginProfile", "UpdateLoginProfile") AND target != "" AND target != caller,
           "console_password_for_another_user",
         event.action LIKE "Attach*" AND (params LIKE "*AdministratorAccess*" OR params LIKE "*IAMFullAccess*"),
           "admin_policy_attached",
         event.action LIKE "Put*" AND wildcard_action IS NOT NULL, "wildcard_inline_policy",
         event.action == "UpdateAssumeRolePolicy", "role_trust_changed",
         event.action == "AddUserToGroup" AND grp LIKE "*admin*", "added_to_admin_group",
         event.action == "CreateUser", "iam_user_created")
| WHERE finding IS NOT NULL
| EVAL tier = CASE(finding == "iam_user_created", "risk", "alert")
| KEEP @timestamp, tier, finding, event.action, aws.cloudtrail.user_identity.arn, aws.cloudtrail.user_identity.type,
       target, grp, aws.cloudtrail.recipient_account_id, source.ip, user_agent.original, params, _id, _version, _index
```

## Before turning it on

- Check `aws.cloudtrail.request_parameters` on one real `CreateAccessKey` and one `PutRolePolicy`. The GROK patterns
  accept both the integration's `key=value` text and raw JSON with escaped quotes. Confirm against your version.
- **Infrastructure-as-code.** Terraform and CloudFormation pipelines create users, attach policies and change trusts
  as a matter of course. Exclude the pair of the pipeline's role ARN and the account it deploys to. Do not exclude the
  event type.
- **The change-window question (item 5).** If changes outside a window are the signal, add
  `DATE_EXTRACT("hour_of_day", @timestamp)` against your window, in UTC, as a label rather than a filter, so in-window
  changes stay visible.

## What it misses

- **A new role with a permissive trust created outright** (`CreateRole`). It is not matched, because it is common in
  IaC. Read `role_trust_changed` as the narrower case.
- **Identity Center (SSO) permission-set changes** come from `sso.amazonaws.com`, not IAM. They are a later addition.
- **Persistence outside IAM**: a Lambda backdoor, an EC2 user-data change, or a new SSH key on an instance.

## When it fires

Deactivate the new key or login profile first, and investigate second. A key deactivated by mistake is a five-minute
outage. A key left active is a breach. Then read every event by the same `user_identity.arn` since its first sign-in
of the day.
