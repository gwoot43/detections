---
id: S22
name: Several different people signing in successfully from one Entra-registered or joined device
category: entra-signin
status: todo
severity: medium
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004, T1550.001, T1098.005]
data_source: Entra ID interactive and non-interactive sign-in logs (device_detail.device_id)
suppression:
  fields: [device_id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An Entra device ID belongs to one registered or joined device, and a corporate laptop is normally used by one person. Several different people signing in from the same device ID points to one of two things:
- **An attacker device:** a device registered with stolen tokens (S18, S20) is being used to work through several compromised accounts.
- **A shared machine** that nobody declared.

Entra ID Protection has no built-in detection for this, so it has to be built here.

To keep one person with two accounts (`jsmith` and `adm-jsmith`) from firing, the rule strips admin prefixes before counting people. Change the prefix list to match your admin naming convention. Don't add single-letter prefixes if user names use initials, or `a.smith` will be read as an admin account.

## Query
```esql
FROM logs-azure.signinlogs-*
| WHERE azure.signinlogs.category IN ("SignInLogs", "NonInteractiveUserSignInLogs")
  AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
| EVAL device_id = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.device_id), "")),
       dev_name = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.display_name), "")),
       trust = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), "")),
       upn = TO_LOWER(COALESCE(azure.signinlogs.properties.user_principal_name, "")),
       local_part = MV_FIRST(SPLIT(upn, "@")),
       person = REPLACE(local_part, "^(adm|admin|t0|t1|t2)[-_.]", ""),
       is_admin = CASE(local_part RLIKE "(adm|admin|t0|t1|t2)[-_.].*", 1, 0),
       is_prt = CASE(azure.signinlogs.properties.incoming_token_type == "primaryRefreshToken", 1, 0)
| WHERE device_id != "" AND device_id != "00000000-0000-0000-0000-000000000000"
// shared estates: AVD/VDI session hosts, kiosks, hot-desk and lab PCs (replace with your naming)
| WHERE NOT (dev_name LIKE "*avd*" OR dev_name LIKE "*vdi*" OR dev_name LIKE "*kiosk*" OR dev_name LIKE "*shared*")
| STATS people = COUNT_DISTINCT(person), users = VALUES(upn), admin_present = MAX(is_admin), prt_used = MAX(is_prt),
        ips = VALUES(source.ip), networks = VALUES(source.as.organization.name),
        apps = VALUES(azure.signinlogs.properties.app_display_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY device_id, dev_name, trust
| WHERE people >= 2
| EVAL severity = CASE(admin_present == 1 OR prt_used == 1 OR people >= 4, "high", "medium")
| KEEP device_id, dev_name, trust, people, users, severity, admin_present, prt_used, ips, networks, apps, first_seen, last_seen
```
Run hourly with a 24-hour lookback. `REPLACE` uses a Java regex, so `^` anchors it there. `RLIKE` is always anchored and doesn't accept `^`.

## Suppression
Suppress by `device_id` for 24h. Alerts missing a key field are not suppressed. The 24-hour lookback re-evaluates the same device every hour.

## Known false positives / exclusions
- **Shared and hot-desk PCs, AVD and VDI session hosts, training rooms, kiosks.** Exclude them by naming pattern (above), or by `trust` if they are a distinct join type in your estate.
- **IT support signing in on a user's laptop** to fix something. Usually two people, one of them from the service desk. Add your support-team naming if this happens often.
- **A device being reassigned** from a leaver to a new starter without a rebuild. That's a hygiene finding worth knowing about anyway.
- **Personal accounts and guests from other tenants** don't appear in your sign-in logs, so Teams multi-account and browser profiles for other organisations don't cause alerts.

## Triage
- Do the users have anything in common: same phishing campaign (E-rules), same team, all risky (I07)? Unrelated users from different departments on one device is the attacker-device pattern.
- `trust` of `azure ad registered` (not joined) on a device no one recognises, combined with S18 or S20 for the same device, means a rogue registration. Delete the device and revoke sessions for every listed user.
- `prt_used`: a primary refresh token issued for several people on one device is the strongest variant.

## Test
Sign in with two different lab accounts on one Entra-joined test device within the hour.
