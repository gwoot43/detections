---
id: X02
name: Identity compromise fan-out: risky sign-in then persistence or privilege action
category: correlation
status: todo
severity: critical
language: esql
index: logs-azure.signinlogs-*, logs-azure.auditlogs-*, logs-o365.audit-*
mitre: [T1078.004, T1098, T1528, T1114.003]
data_source: Entra sign-in (I07/I08) + Entra audit (C03/C04/C05/I10) + O365 inbox rules (E06) joined on the UPN
suppression:
  fields: [usr]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A single risky sign-in is a maybe. A risky or device-code sign-in followed by any of: a new MFA method, an inbox rule, an app consent, a credential added to an app, or a role assignment, performed by the same user, is the textbook account-takeover-to-persistence chain. The sequence is what makes it certain.

## Query
```esql
FROM logs-azure.signinlogs-*, logs-azure.auditlogs-*, logs-o365.audit-*
| WHERE @timestamp > NOW() - 2 hours
| EVAL risk = TO_LOWER(azure.signinlogs.properties.risk_level_during_signin),
       risk_types = TO_LOWER(MV_CONCAT(TO_STRING(azure.signinlogs.properties.risk_event_types_v2), ",")),
       proto = TO_LOWER(azure.signinlogs.properties.authentication_protocol),
       op = TO_LOWER(azure.auditlogs.operation_name)
// risky: a successful sign-in that Entra rated medium or high, carries a token-theft or hostile-IP detection, or used device code
| EVAL risky = event.dataset == "azure.signinlogs" AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
         AND (risk IN ("medium", "high") OR proto == "devicecode"
              OR risk_types LIKE "*anomaloustoken*" OR risk_types LIKE "*tokenissueranomaly*"
              OR risk_types LIKE "*maliciousipaddress*" OR risk_types LIKE "*impossibletravel*"),
// persistence: performed by the user, so the key is the initiator and not the target
       persist = (event.dataset == "azure.auditlogs" AND azure.auditlogs.properties.result == "success"
                  AND (op IN ("user registered security info", "user changed default security info", "admin registered security info",
                              "consent to application", "add delegated permission grant", "add service principal credentials",
                              "add app role assignment to service principal")
                       OR op LIKE "add member to role*" OR op LIKE "add eligible member to role*"
                       OR op LIKE "*certificates and secrets management*"))
              OR (event.dataset == "o365.audit" AND event.action IN ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Enable-InboxRule"))
| WHERE risky OR persist
| EVAL usr = TO_LOWER(CASE(event.dataset == "azure.signinlogs", user.name,
                           event.dataset == "azure.auditlogs", azure.auditlogs.properties.initiated_by.user.userPrincipalName,
                           o365.audit.UserId)),
       risk_ts = CASE(risky, @timestamp, NULL),
       persist_ts = CASE(persist, @timestamp, NULL),
       persist_action = CASE(persist, COALESCE(op, TO_LOWER(event.action)), NULL),
       risk_detail = CASE(risky, CONCAT(COALESCE(risk, "none"), " | ", COALESCE(proto, ""), " | ", COALESCE(risk_types, "")), NULL),
       signin_ip = CASE(risky, TO_STRING(source.ip), NULL),
       signin_country = CASE(risky, source.geo.country_iso_code, NULL),
       signin_app = CASE(risky, azure.signinlogs.properties.app_display_name, NULL)
| WHERE usr IS NOT NULL
| STATS first_risky = MIN(risk_ts), last_persist = MAX(persist_ts),
        persist_actions = VALUES(persist_action), risk_details = VALUES(risk_detail),
        signin_ips = VALUES(signin_ip), signin_countries = VALUES(signin_country), signin_apps = VALUES(signin_app)
    BY usr
| WHERE first_risky IS NOT NULL AND last_persist IS NOT NULL AND last_persist >= first_risky
| EVAL minutes_signin_to_persist = DATE_DIFF("minute", first_risky, last_persist)
| KEEP usr, first_risky, last_persist, minutes_signin_to_persist, persist_actions, risk_details, signin_ips, signin_countries, signin_apps
```
Run every 30 minutes. The 2-hour lookback is the correlation window: the persistence action must come after the risky sign-in, anywhere inside it. Entra sign-in and audit events can arrive 5-30 minutes late, which the 2-hour window absorbs.

All three sources carry the full UPN (`user.name` on sign-ins, `initiated_by.user.userPrincipalName` on audit, `o365.audit.UserId` on Exchange), so the key needs no stripping, only lowercasing.

Field notes:
- `risk_event_types_v2` is multi-valued. It's joined into one string before `LIKE`, which returns nothing on a multi-valued field.
- Operation names are matched exactly, so "User started security info registration", "User deleted security info" and "Add app role assignment grant to user" (ordinary app assignment) don't count.
- Inbox rules are not in the Entra audit log. They come from the O365 audit log (Exchange), which is why it's the third source.

## Suppression
Suppress by `usr` for 24h. Alerts missing a key field are not suppressed. Correlation rule: one alert per compromised account. Later persistence actions by the same account fold into it and raise the suppressed count, which you should read.

## Known false positives / exclusions
- A user who genuinely triggers a risk flag (travel) and legitimately registers a new phone in the same window. Rare, and worth the phone call anyway.
- A new joiner whose first sign-in is rated risky and who then registers MFA. Check the account creation date.

## Triage
- Full account-takeover response: revoke sessions and refresh tokens, reset password, remove the attacker's persistence (MFA method, rule, consent, credential, role), and audit what was accessed.

## Test
On a lab account, simulate a risky sign-in (for example, from an anonymising VPN) then register an MFA method within the hour.
