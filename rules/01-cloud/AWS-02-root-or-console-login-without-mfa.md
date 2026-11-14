---
id: AWS-02
name: AWS root account used, or an IAM user signed in to the console without MFA
category: cloud
status: todo
language: esql
index: logs-aws.cloudtrail-*
mitre: [T1078.004]
data_source: AWS CloudTrail management events (Elastic AWS integration)
suppression:
  fields: [aws.cloudtrail.user_identity.arn, source.ip]
  duration: 6h
  missing_fields: do_not_suppress
---

**Not collected in this estate yet.** The catalogue's only AWS rule (`AWS-01`) reads Falcon process events. CloudTrail
is not ingested. This rule targets the Elastic AWS integration's CloudTrail stream, so it is ready when that feed is.
Run the probe first.

The root user should be locked away: hardware MFA, no access keys, used for the few tasks only root can do. Any root
activity is therefore an event a person can explain within minutes, or an account takeover. A console sign-in by an
IAM user without MFA is the same question one level down. Federated (SSO) users never appear here, because their MFA
happens at the identity provider and the session arrives as an assumed role.

Both are low volume and high signal. **Alert grade.**

## Query

Run every 5 minutes with a 10-minute lookback.

```esql
FROM logs-aws.cloudtrail-* METADATA _id, _index, _version
| WHERE aws.cloudtrail.user_identity.type == "Root"
   OR (event.action == "ConsoleLogin" AND aws.cloudtrail.user_identity.type == "IAMUser")
| EVAL mfa_used = TO_STRING(aws.cloudtrail.console_login.additional_eventdata.mfa_used),
       invoked_by = COALESCE(aws.cloudtrail.user_identity.invoked_by, "")
| EVAL finding = CASE(aws.cloudtrail.user_identity.type == "Root" AND event.action == "ConsoleLogin", "root_console_login",
                      aws.cloudtrail.user_identity.type == "Root", "root_api_activity",
                      event.outcome == "success" AND mfa_used == "false", "iam_user_console_login_without_mfa")
// an AWS service acting under root on your behalf (invoked_by set) is not a person using root
| WHERE finding IS NOT NULL AND invoked_by == ""
| KEEP @timestamp, finding, event.action, event.provider, event.outcome, aws.cloudtrail.user_identity.arn,
       aws.cloudtrail.recipient_account_id, source.ip, source.as.organization.name, user_agent.original, mfa_used,
       aws.cloudtrail.error_code, _id, _version, _index
```

## Before turning it on

```esql
FROM logs-aws.cloudtrail-*
| WHERE @timestamp >= NOW() - 7 days
| STATS events = COUNT(*), root_events = COUNT(*) WHERE aws.cloudtrail.user_identity.type == "Root",
        console_logins = COUNT(*) WHERE event.action == "ConsoleLogin"
    BY aws.cloudtrail.recipient_account_id
```

- No rows means CloudTrail is not ingested, so stop here.
- Confirm that `aws.cloudtrail.console_login.additional_eventdata.mfa_used` is populated on one real `ConsoleLogin`.
  If it is null on every row, the integration version maps it differently, and the no-MFA branch silently never
  fires.
- An organisation trail delivers all member accounts. A single-account trail covers only that account.

## What it misses

- **Root access-key use from an account where keys should not exist.** It is caught as `root_api_activity`, but the
  real fix is to delete the keys, and AWS Config's `iam-root-access-key-check` reports them.
- **SSO users with weak MFA.** That lives in the identity provider's logs (Entra, Okta), not CloudTrail.
- **A failed root login** shows as `root_console_login` with `event.outcome` failure. Worth reading, but it is not a
  compromise on its own.

## When it fires

For root, confirm with the account owner within minutes. If it was not them, reset the root password, re-enrol MFA,
delete any access keys, and review `AWS-03` (IAM persistence) and `AWS-05` (logging disabled) for the same account
since `@timestamp`.
