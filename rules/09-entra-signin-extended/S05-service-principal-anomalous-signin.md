---
id: S05
name: Service principal sign-in from a new network, or secret-guessing failures
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004, T1528, T1110]
data_source: Entra ID service principal sign-in logs
---
## Why this is high fidelity
Service principals authenticate from fixed infrastructure (your pipelines, your Azure subscriptions). One appearing from a second ASN or country in the same day means its secret or certificate is in use elsewhere, which is exactly what a leaked credential looks like (and the natural follow-on to C04). A burst of invalid-secret failures (7000215) is someone testing stolen or guessed secrets.

## Query
```esql
FROM logs-azure.signinlogs-*
| WHERE azure.signinlogs.category == "ServicePrincipalSignInLogs"
| EVAL sp = TO_LOWER(TO_STRING(azure.signinlogs.properties.service_principal_name)),
       ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       ok = CASE(ec == "0", 1, 0),
       bad_secret = CASE(ec IN ("7000215", "7000222", "700016"), 1, 0)
| STATS successes = SUM(ok), bad_secrets = SUM(bad_secret),
        asns = COUNT_DISTINCT(source.as.organization.name), asn_list = VALUES(source.as.organization.name),
        countries = COUNT_DISTINCT(source.geo.country_iso_code), where_from = VALUES(source.geo.country_iso_code),
        ips = VALUES(source.ip), resources = VALUES(azure.signinlogs.properties.resource_display_name)
    BY sp, BUCKET(@timestamp, 24 hours)
| WHERE (successes > 0 AND (asns >= 2 OR countries >= 2)) OR bad_secrets >= 10
```

## Known false positives / exclusions
- Service principals used from both a cloud subscription and an on-prem build agent by design. Baseline each SP's expected ASN set in a lookup and alert on deviation instead of on the raw count.

## Triage
- Rotate the SP credential, review C04 for who added it, and check the SP's permissions for what the attacker could reach. Revoking the credential invalidates tokens at expiry only; also review the SP's recent Graph and ARM activity.

## Test
Authenticate a test SP from a lab VM in a different cloud region or from a home connection.
