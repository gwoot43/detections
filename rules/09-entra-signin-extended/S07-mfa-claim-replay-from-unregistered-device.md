---
id: S07
name: MFA satisfied by an existing token claim from an unregistered device on hosting or anonymizer infrastructure
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1550.001, T1557, T1078.004]
data_source: Entra ID sign-in logs (authentication details)
suppression:
  fields: [user.name, source.ip]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
After an adversary-in-the-middle phish (Evilginx-class) the attacker replays the stolen session. The sign-in shows MFA as satisfied, but by a claim already in the token, not by a fresh challenge, from a browser on a device that is not registered or joined, from an IP that belongs to a hosting provider or VPN rather than a home or corporate network. Each of those on its own is common; all three together is session theft.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE azure.signinlogs.category IN ("SignInLogs", "NonInteractiveUserSignInLogs")
  AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
// the integration folds status.additionalDetails into message ("MFA requirement satisfied by claim in the token")
| EVAL detail = TO_LOWER(COALESCE(message, "")),
       trust = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), "")),
       asn = TO_LOWER(COALESCE(source.as.organization.name, "")),
       req = TO_LOWER(TO_STRING(azure.signinlogs.properties.authentication_requirement))
| WHERE req == "multifactorauthentication"
  AND detail LIKE "*mfa requirement satisfied by claim in the token*"
  AND trust == ""                                           // not Entra joined, hybrid joined or registered
  AND (asn LIKE "*digitalocean*" OR asn LIKE "*m247*" OR asn LIKE "*vultr*" OR asn LIKE "*linode*" OR asn LIKE "*ovh*" OR asn LIKE "*hetzner*"
       OR asn LIKE "*choopa*" OR asn LIKE "*leaseweb*" OR asn LIKE "*contabo*" OR asn LIKE "*amazon*" OR asn LIKE "*google*cloud*"
       OR asn LIKE "*nordvpn*" OR asn LIKE "*expressvpn*" OR asn LIKE "*mullvad*" OR asn LIKE "*private internet access*" OR asn LIKE "*datacamp*" OR asn LIKE "*packethub*")
| WHERE NOT CIDR_MATCH(source.ip, "203.0.113.0/24")     // corporate egress or VPN that sits in a cloud ASN
| KEEP @timestamp, user.name, source.ip, asn, source.geo.country_iso_code, azure.signinlogs.properties.app_display_name, user_agent.original, trust, detail
```
Keep the ASN list in step with S10 and grow it from your own alerts. If you licence Identity Protection, `risk_event_types_v2` containing `anonymizedIPAddress` or `anomalousToken` is a cleaner third condition than the ASN list.

The old `mfa_detail` condition was removed: it is an object, not a field ES|QL can read, and the sample data carries it empty. A Microsoft Azure ASN pattern was also removed: MaxMind names that network `MICROSOFT-CORP-MSN-AS-BLOCK`, so the pattern never matched, and Azure egress is shared with Windows 365 and Azure Virtual Desktop users.

## Suppression
Suppress by `user.name`, `source.ip` for 24h. Alerts missing a key field are not suppressed. A replayed session keeps refreshing. A new IP still alerts.

## Known false positives / exclusions
- Staff on a personal VPN from an unmanaged laptop. Your BYOD policy decides whether that is acceptable; if it is, require `is_compliant == false` plus the ASN list and raise the bar to sensitive apps only.

## Triage
- Revoke the user's sessions and refresh tokens immediately (the password is not the problem; the session is). Then look for E06 inbox rules, I10 MFA registrations and C05 consents in the following hour.

## Test
Sign in with a lab account from a browser on an unregistered VM in a cloud provider, using an existing session cookie.
