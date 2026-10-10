---
id: S10
name: Successful workforce sign-in from hosting, VPN or anonymizer infrastructure
category: entra-signin
status: todo
severity: medium
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004, T1090.003]
data_source: Entra ID sign-in logs
suppression:
  fields: [user.name, source.ip]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Employees sign in from ISPs, mobile carriers and your corporate egress. Attackers sign in from cloud VMs, residential-proxy networks and commercial VPNs. Restricting to successful sign-ins to sensitive resources, from a device the tenant does not know, from a curated ASN list gives a signal that does not depend on Identity Protection licensing and complements S07.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
  AND azure.signinlogs.category == "SignInLogs"
| EVAL asn = TO_LOWER(COALESCE(source.as.organization.name, "")), res = TO_LOWER(TO_STRING(azure.signinlogs.properties.resource_display_name)),
       trust = COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), "")
| WHERE (asn LIKE "*digitalocean*" OR asn LIKE "*m247*" OR asn LIKE "*vultr*" OR asn LIKE "*linode*" OR asn LIKE "*ovh*" OR asn LIKE "*hetzner*" OR asn LIKE "*choopa*" OR asn LIKE "*leaseweb*" OR asn LIKE "*contabo*"
        OR asn LIKE "*nordvpn*" OR asn LIKE "*expressvpn*" OR asn LIKE "*mullvad*" OR asn LIKE "*private internet access*" OR asn LIKE "*datacamp*" OR asn LIKE "*packethub*" OR asn LIKE "*tor *" OR asn LIKE "*bright data*" OR asn LIKE "*oxylabs*")
  AND (res LIKE "*exchange*" OR res LIKE "*sharepoint*" OR res LIKE "*graph*" OR res LIKE "*azure service management*" OR res LIKE "*office 365*")
  AND trust == ""                                       // a registered or joined corporate device behind a VPN is not the attacker
| WHERE NOT CIDR_MATCH(source.ip, "203.0.113.0/24")     // corporate egress that happens to sit in a hosting ASN
| KEEP @timestamp, user.name, source.ip, asn, source.geo.country_iso_code, res, azure.signinlogs.properties.app_display_name, azure.signinlogs.properties.device_detail.operating_system, user_agent.original
```

## Suppression
Suppress by `user.name`, `source.ip` for 24h. Alerts missing a key field are not suppressed. Sessions from the same exit keep refreshing.

## Known false positives / exclusions
- Staff using a personal VPN on a personal device. Staff on a corporate (registered or joined) device are already excluded. If the rest is still common in your workforce, keep the rule as enrichment for other alerts rather than a standalone page. Corporate services hosted in a listed cloud ASN (your own Azure egress) must be excluded by CIDR.

## Triage
- Compare against the user's normal locations and devices. If the same sign-in also satisfied MFA from a token claim (S07), treat it as session replay.

## Test
Sign in with a lab account through a commercial VPN.
