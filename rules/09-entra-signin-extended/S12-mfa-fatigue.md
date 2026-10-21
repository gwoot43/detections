---
id: S12
name: MFA fatigue (repeated denied or unanswered MFA prompts), and whether one was then accepted
category: entra-signin
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1621, T1110]
data_source: Entra ID interactive sign-in logs
suppression:
  fields: [usr, outcome]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Error 500121 means the password was correct but the MFA step failed: the user denied the prompt, ignored it, or reported it as fraud. A burst of these for one user means someone else has the password and is sending prompts, hoping the user eventually approves. Users rarely deny their own prompts more than once or twice. A fraud report from the Authenticator app is a deliberate signal from the user and alerts on its own.

Failures are only counted from devices the tenant does not know. The attacker sends prompts from their own machine; a user whose phone is flat and who retries from their managed laptop does not count.

The `outcome` column says how it ended:
- **`accepted`** when a sign-in then succeeds from an IP that was sending the prompts: the user gave in.
- **`reported_as_fraud`** when the user reported a prompt as fraud.
- **`denied_only`** for a burst of denials with no acceptance.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs" AND azure.signinlogs.category == "SignInLogs"
// the integration folds status.failureReason and status.additionalDetails into message
| EVAL ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       detail = TO_LOWER(COALESCE(message, "")),
       trust = COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), ""),
       usr = TO_LOWER(user.name)
| EVAL mfa_fail = CASE(ec == "500121" AND trust == "", 1, 0),
       fraud = CASE(ec == "500121" AND detail LIKE "*fraud*", 1, 0),
       ok = CASE(ec == "0", 1, 0)
| WHERE mfa_fail == 1 OR fraud == 1 OR ok == 1
// stage 1: per user and IP, so an acceptance is only counted from an IP that was also prompting
| STATS f = SUM(mfa_fail), fr = SUM(fraud), s = SUM(ok),
        first_f = MIN(CASE(mfa_fail == 1, @timestamp, NULL)),
        last_s = MAX(CASE(ok == 1, @timestamp, NULL)),
        country = VALUES(source.geo.country_iso_code),
        app = VALUES(azure.signinlogs.properties.app_display_name)
    BY usr, source.ip
| EVAL accepted_here = CASE(f > 0 AND s > 0 AND last_s >= first_f, 1, 0)
// stage 2: per user
| STATS mfa_failures = SUM(f), fraud_reports = SUM(fr), accepted_ips = SUM(accepted_here),
        prompting_ips = COUNT_DISTINCT(CASE(f > 0, source.ip, NULL)),
        ips = VALUES(CASE(f > 0, source.ip, NULL)),
        countries = VALUES(country), apps = VALUES(app)
    BY usr
| WHERE mfa_failures >= 5 OR fraud_reports >= 1
| EVAL outcome = CASE(accepted_ips > 0, "accepted", fraud_reports >= 1, "reported_as_fraud", "denied_only")
```
The integration removes `status.additional_details` and writes it into `message` as "failure reason (additional details)", so the fraud branch reads `message`. It carries text such as "MFA denied; user declined the authentication" and "MFA denied; Phone App Reported Fraud".

## Suppression
Suppress by `usr`, `outcome` for 4h. Alerts missing a key field are not suppressed. Aggregating rule. `outcome` is in the key, so a burst that later turns into an accepted prompt raises a new alert instead of folding into the open one.

## Known false positives / exclusions
- A user who keeps declining because their phone was replaced or the app is misconfigured. This usually comes with a help-desk ticket the same day.
- Number matching in Microsoft Authenticator reduces push approval by accident, but attackers also use phone call and SMS methods, so keep the rule on.

## Triage
- **`accepted`:** revoke the user's sessions and refresh tokens, reset the password, and check for a newly registered MFA method (I10), inbox rules (E06) and consent grants (C05) in the next hour.
- **`reported_as_fraud` or `denied_only`:** the password is known to someone else. Reset it, revoke sessions, and contact the user to confirm they did not trigger the prompts. Check S13, S14 and S15 for how the password was obtained.

## Test
With a lab account, trigger five sign-ins from an unregistered lab device and decline each MFA prompt, then approve one.
