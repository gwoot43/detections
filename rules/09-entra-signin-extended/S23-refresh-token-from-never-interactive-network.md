---
id: S23
name: Non-interactive (refresh token) sign-in from a network the user has never signed in from interactively
category: entra-signin
status: todo
severity: medium
language: esql
index: logs-azure.signinlogs-*
mitre: [T1550.001, T1528, T1539]
data_source: Entra ID interactive and non-interactive sign-in logs (source.as.number)
suppression:
  fields: [upn, asn]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Non-interactive sign-ins are a client silently redeeming a refresh token. Normally that happens on the same device and network where the user signed in interactively. A stolen refresh token or session (AiTM phishing kit, token theft from a browser or TokenSmith-style tooling) is redeemed from the attacker's infrastructure, with no interactive sign-in from that network, ever.

The rule looks back 7 days per user and network (ASN). It fires when a network appears for the first time in the last hour, only in non-interactive sign-ins from a device the tenant does not know, and never once with an interactive sign-in. This complements S08 (one session ID across networks) and I07 (Microsoft's token risk detections), and catches replay when the session ID is missing or Identity Protection stays quiet.

## Query
```esql
FROM logs-azure.signinlogs-*
| WHERE azure.signinlogs.category IN ("SignInLogs", "NonInteractiveUserSignInLogs")
  AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
  AND source.as.number IS NOT NULL
  // Microsoft's own network: first-party services sometimes redeem tokens on the user's behalf from Azure
  AND source.as.number != 8075
| EVAL upn = TO_LOWER(COALESCE(azure.signinlogs.properties.user_principal_name, "")),
       asn = source.as.number,
       trust = COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), ""),
       interactive = CASE(azure.signinlogs.category == "SignInLogs", 1, 0),
       nonint_ts = CASE(azure.signinlogs.category == "NonInteractiveUserSignInLogs", @timestamp, NULL),
       nonint_known_device = CASE(azure.signinlogs.category == "NonInteractiveUserSignInLogs" AND trust != "", 1, 0)
| STATS interactive_signins = SUM(interactive), known_device_refreshes = SUM(nonint_known_device),
        first_seen = MIN(@timestamp), first_nonint = MIN(nonint_ts),
        last_nonint = MAX(nonint_ts), nonint_signins = COUNT(nonint_ts),
        network = VALUES(source.as.organization.name), countries = VALUES(source.geo.country_iso_code),
        ips = VALUES(source.ip), apps = VALUES(azure.signinlogs.properties.app_display_name),
        resources = VALUES(azure.signinlogs.properties.resource_display_name)
    BY upn, asn
// a network seen for the first time in the last hour, only through refreshes, and only from unregistered devices
| WHERE interactive_signins == 0 AND nonint_signins > 0 AND known_device_refreshes == 0
  AND DATE_DIFF("minute", first_seen, NOW()) <= 60
| KEEP upn, asn, network, countries, ips, apps, resources, first_nonint, last_nonint, nonint_signins
```
Run hourly with a **7-day lookback**. The lookback is the user's baseline, so a shorter one makes every network look new. Non-interactive sign-in logs are high volume, so check the query time on your tenant. If it's too slow, cut to 3 days or limit it to Exchange, SharePoint and Graph resources.

Refreshes from a registered or joined device are not counted. The user's own phone (Authenticator or Company Portal registers it) and laptop (PRT) carry a trust type; a replayed refresh token or session cookie does not. That removes the bulk of the "phone on a new Wi-Fi network" noise.

## Suppression
Suppress by `upn`, `asn` for 24h. Alerts missing a key field are not suppressed. A replayed token keeps refreshing from the same network all day.

## Known false positives / exclusions
- **Unregistered phones or tablets changing networks** (roaming abroad, a new carrier, a hotel's Wi-Fi), where the mail or Teams app refreshes silently and the user never signs in interactively there. Raise to high severity only when the country is also new (check I07 and S08), or when `network` is a hosting provider (S07).
- **Microsoft's network (ASN 8075)** is excluded because first-party services redeem tokens from Azure. That also hides an attacker renting an Azure VM. S07 does not cover Azure either, because Windows 365 and Azure Virtual Desktop users share that ASN.

## Triage
- Compare `network` and `countries` with where the user really is. A hosting or VPN provider, or a country the user has never been in, means token replay. Revoke sessions (`Revoke-MgUserSignInSession`), reset the password, and check S11 and I10 for persistence added since.
- Look for the phishing message that started it: AiTM kits steal the session at the first interactive sign-in. Check E-rules and Zscaler (N07) for clicks a few hours before `first_nonint`.

## Test
Sign in as a lab user on one network, then use the same browser profile, copied to a cloud VM outside Azure, to open Outlook on the web without signing in again. The VM's network should alert within the hour.
