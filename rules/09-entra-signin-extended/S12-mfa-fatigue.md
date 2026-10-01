---
id: S12
name: MFA fatigue (repeated denied or unanswered MFA prompts), critical if then accepted
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1621, T1110]
data_source: Entra ID interactive sign-in logs
suppression:
  fields: [usr, severity]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Error 500121 means the password was correct but the MFA step failed: the user denied the prompt, ignored it, or reported it as fraud. A burst of these for one user means someone else has the password and is sending prompts, hoping the user eventually approves. Users rarely deny their own prompts more than once or twice. A fraud report from the Authenticator app is a deliberate signal from the user and alerts on its own.

Severity is computed per alert:
- **critical** when a sign-in then succeeds from an IP that was sending the prompts: the user gave in.
- **high** when the user reported a prompt as fraud.
- **medium** for a burst of denials with no acceptance.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs" AND azure.signinlogs.category == "SignInLogs"
| EVAL ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       detail = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.status.additional_details), "")),
       usr = TO_LOWER(user.name)
| EVAL mfa_fail = CASE(ec == "500121", 1, 0),
       fraud = CASE(ec == "500121" AND detail LIKE "*fraud*", 1, 0),
       ok = CASE(ec == "0", 1, 0)
| WHERE mfa_fail == 1 OR ok == 1
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
| EVAL severity = CASE(accepted_ips > 0, "critical", fraud_reports >= 1, "high", "medium")
```
Confirm `status.additional_details` is populated in your integration. It carries text such as "MFA denied; user declined the authentication" and "MFA denied; Phone App Reported Fraud". Without it the fraud branch is silent but the burst and acceptance logic still work.

## Suppression
Suppress by `usr`, `severity` for 4h. Alerts missing a key field are not suppressed. Aggregating rule. Severity is in the key, so a burst that later turns into an accepted prompt raises a new critical alert instead of folding into the open medium one.

## Known false positives / exclusions
- A user who keeps declining because their phone was replaced or the app is misconfigured. This usually comes with a help-desk ticket the same day.
- Number matching in Microsoft Authenticator reduces push approval by accident, but attackers also use phone call and SMS methods, so keep the rule on.

## Triage
- **critical:** revoke the user's sessions and refresh tokens, reset the password, and check for a newly registered MFA method (I10), inbox rules (E06) and consent grants (C05) in the next hour.
- **high or medium:** the password is known to someone else. Reset it, revoke sessions, and contact the user to confirm they did not trigger the prompts. Check I05, S13 and S14 for how the password was obtained.

## Test
With a lab account, trigger five sign-ins from another device and decline each MFA prompt, then approve one.
