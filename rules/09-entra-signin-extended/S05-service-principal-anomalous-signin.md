---
id: S05
name: Service principal sign-in from a new network, or secret-guessing failures
category: entra-signin
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004, T1528, T1110]
data_source: Entra ID service principal sign-in logs
suppression:
  fields: [sp]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Service principals authenticate from fixed infrastructure (your pipelines, your Azure subscriptions). One that succeeds from a network (ASN) it has not used in the past week means its secret or certificate is in use elsewhere, which is exactly what a leaked credential looks like (and the natural follow-on to C04). A burst of invalid-secret failures (7000215) from a network where the service principal never succeeds is someone holding an old or guessed secret.

Both branches need a baseline: the service principal must also have succeeded from a known network before the last hour. That keeps out brand-new service principals and ones that are simply broken everywhere. Expired-secret (7000222) and unknown-application (700016) errors were dropped: the first is a stale deployment retrying, and the second has no service principal to group on.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-azure.signinlogs-*
| WHERE azure.signinlogs.category == "ServicePrincipalSignInLogs"
  AND source.as.number IS NOT NULL
| EVAL sp = TO_LOWER(TO_STRING(azure.signinlogs.properties.service_principal_name)),
       ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       ok = CASE(ec == "0", 1, 0),
       bad_secret = CASE(ec == "7000215", 1, 0)
| WHERE sp IS NOT NULL AND (ok == 1 OR bad_secret == 1)
// stage 1: per service principal and network over the 7-day lookback
| STATS successes = SUM(ok), bad_secrets = SUM(bad_secret),
        first_ok = MIN(CASE(ok == 1, @timestamp, NULL)),
        last_bad = MAX(CASE(bad_secret == 1, @timestamp, NULL)),
        net = VALUES(source.as.organization.name), ctry = VALUES(source.geo.country_iso_code), ip = VALUES(source.ip),
        res = VALUES(azure.signinlogs.properties.resource_display_name)
    BY sp, source.as.number
| EVAL known_net = CASE(successes > 0 AND first_ok < NOW() - 1 hour, 1, 0),
       new_net = CASE(successes > 0 AND first_ok >= NOW() - 1 hour, 1, 0),
       guessing_net = CASE(successes == 0 AND bad_secrets >= 10 AND last_bad >= NOW() - 1 hour, 1, 0)
// stage 2: per service principal
| STATS known_networks = SUM(known_net), new_networks = SUM(new_net), guessing_networks = SUM(guessing_net),
        guess_failures = SUM(bad_secrets * guessing_net),
        flagged_asns = VALUES(CASE(new_net == 1 OR guessing_net == 1, net, NULL)),
        flagged_countries = VALUES(CASE(new_net == 1 OR guessing_net == 1, ctry, NULL)),
        flagged_ips = VALUES(CASE(new_net == 1 OR guessing_net == 1, ip, NULL)),
        resources = VALUES(CASE(new_net == 1, res, NULL))
    BY sp
| WHERE known_networks > 0 AND (new_networks > 0 OR guessing_networks > 0)
```
Service principal sign-in volume can be large. Check the query time on your tenant; if it is too slow, cut the lookback to 3 days.

## Suppression
Suppress by `sp` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. The 7-day lookback re-evaluates the same service principal every hour.

## Known false positives / exclusions
- A pipeline moved to new build agents or a new cloud. It shows as one new network the day of the change. Confirm against the change record.
- A service principal used from both a cloud subscription and an on-prem build agent by design is fine once both networks are in the 7-day baseline.
- A forgotten deployment still using a rotated secret fails from its own network every day and keeps the guessing branch firing. Find and remove it: an old secret sitting in a config somewhere is the same exposure an attacker would use.

## Triage
- Rotate the SP credential, review C04 for who added it, and check the SP's permissions for what the attacker could reach. Revoking the credential invalidates tokens at expiry only; also review the SP's recent Graph and ARM activity.

## Test
Authenticate a lab SP that already has a week of sign-ins from its usual host, then from a lab VM on a different network.
