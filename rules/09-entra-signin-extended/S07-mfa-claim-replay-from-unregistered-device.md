---
id: S07
name: Sign-in from hosting, VPN or anonymizer infrastructure on an unregistered device, or with MFA satisfied by a replayed token claim
category: entra-signin
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1550.001, T1557, T1078.004, T1090.003]
data_source: Entra ID sign-in logs (authentication details)
suppression:
  fields: [user.name, source.ip, finding]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Employees sign in from ISPs, mobile carriers and your corporate egress. Attackers sign in from cloud VMs, residential-proxy networks and commercial VPNs. Both tiers need a successful sign-in from a device the tenant does not know (not registered or joined), from an IP in a curated hosting, VPN or anonymizer ASN list. That does not depend on Identity Protection licensing.

- **`token_claim_replay`:** after an adversary-in-the-middle phish (Evilginx-class) the attacker replays the stolen session. The sign-in shows MFA as satisfied, but by a claim already in the token, not by a fresh challenge. Each of the three conditions (token-claim MFA, unregistered device, hosting or anonymizer IP) is common on its own; all three together is session theft. Interactive and non-interactive sign-ins both count.
- **`unregistered_device_sensitive_app`:** the same infrastructure and an unregistered device, without the token-claim evidence, on an interactive sign-in to a sensitive resource (Exchange, SharePoint, Graph, Azure management, Office 365). This is the wider net: it catches a stolen password used from a VPS or proxy.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE azure.signinlogs.category IN ("SignInLogs", "NonInteractiveUserSignInLogs")
  AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
// the integration folds status.additionalDetails into message ("MFA requirement satisfied by claim in the token")
| EVAL detail = TO_LOWER(COALESCE(message, "")),
       trust = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), "")),
       asn = TO_LOWER(COALESCE(source.as.organization.name, "")),
       req = TO_LOWER(TO_STRING(azure.signinlogs.properties.authentication_requirement)),
       res = TO_LOWER(TO_STRING(azure.signinlogs.properties.resource_display_name))
| WHERE trust == ""                                           // not Entra joined, hybrid joined or registered
  AND (asn LIKE "*digitalocean*" OR asn LIKE "*m247*" OR asn LIKE "*vultr*" OR asn LIKE "*linode*" OR asn LIKE "*ovh*" OR asn LIKE "*hetzner*"
       OR asn LIKE "*choopa*" OR asn LIKE "*leaseweb*" OR asn LIKE "*contabo*" OR asn LIKE "*amazon*" OR asn LIKE "*google*cloud*"
       OR asn LIKE "*nordvpn*" OR asn LIKE "*expressvpn*" OR asn LIKE "*mullvad*" OR asn LIKE "*private internet access*" OR asn LIKE "*datacamp*" OR asn LIKE "*packethub*"
       OR asn LIKE "*tor *" OR asn LIKE "*bright data*" OR asn LIKE "*oxylabs*")
| WHERE NOT CIDR_MATCH(source.ip, "203.0.113.0/24")     // corporate egress or VPN that sits in a cloud ASN
| EVAL finding = CASE(
         req == "multifactorauthentication" AND detail LIKE "*mfa requirement satisfied by claim in the token*", "token_claim_replay",
         azure.signinlogs.category == "SignInLogs"
           AND (res LIKE "*exchange*" OR res LIKE "*sharepoint*" OR res LIKE "*graph*" OR res LIKE "*azure service management*" OR res LIKE "*office 365*"), "unregistered_device_sensitive_app",
         NULL)
| WHERE finding IS NOT NULL
| KEEP @timestamp, user.name, source.ip, finding, asn, source.geo.country_iso_code, res, azure.signinlogs.properties.app_display_name,
       azure.signinlogs.properties.device_detail.operating_system, user_agent.original, trust, detail, _id, _version, _index
```
Grow the ASN list from your own alerts. If you licence Identity Protection, `risk_event_types_v2` containing `anonymizedIPAddress` or `anomalousToken` is a cleaner condition than the ASN list.

The old `mfa_detail` condition was removed: it is an object, not a field ES|QL can read, and the sample data carries it empty. A Microsoft Azure ASN pattern was also removed: MaxMind names that network `MICROSOFT-CORP-MSN-AS-BLOCK`, so the pattern never matched, and Azure egress is shared with Windows 365 and Azure Virtual Desktop users.

## Suppression
Suppress by `user.name`, `source.ip`, `finding` for 24h. Alerts missing a key field are not suppressed. A replayed session keeps refreshing, and a new IP still alerts. `finding` is in the key so a sign-in from an IP that later shows token-claim replay raises a new alert.

## Known false positives / exclusions
- Staff on a personal VPN from an unmanaged laptop or phone. Staff on a corporate (registered or joined) device are already excluded. Your BYOD policy decides whether the rest is acceptable; if it is common in your workforce, keep the medium tier as enrichment for other alerts rather than a standalone page, or require `is_compliant == false` and sensitive apps only for the high tier.
- Corporate services and cloud desktops hosted in a listed cloud ASN (your own Amazon or Google egress, Amazon WorkSpaces). Exclude them by CIDR.

## Triage
- **`token_claim_replay`:** revoke the user's sessions and refresh tokens immediately (the password is not the problem; the session is). Then look for E06 inbox rules, I10 MFA registrations and C05 consents in the following hour.
- **`unregistered_device_sensitive_app`:** compare against the user's normal locations and devices. If the user does not recognise the sign-in, treat the password as stolen: reset it, revoke sessions, and check for the same follow-on persistence.

## Test
Sign in with a lab account through a commercial VPN from an unregistered machine: `unregistered_device_sensitive_app`. Sign in from a browser on an unregistered VM in a cloud provider using an existing session cookie: `token_claim_replay`.
