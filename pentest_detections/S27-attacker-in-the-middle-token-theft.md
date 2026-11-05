---
id: S27
name: Attacker in the middle - authentication through a malicious reverse proxy, and PRT access attempts
category: entra-signin-extended
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1557, T1539, T1528]
data_source: Entra ID Protection risk detections in the sign-in log (attackerinTheMiddle, attemptedPrtAccess)
references: [https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks]
suppression:
  fields: [user.id]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

Microsoft describes **Attacker in the Middle** as a *high precision* detection: it fires when an authentication
session is linked to a malicious reverse proxy, the phishing-kit pattern where the user completes MFA on the real
tenant while the proxy keeps the issued token. The credentials and the tokens are both intercepted, so a password
change alone does not end it - the sessions have to be revoked.

`I07` covers high-risk sign-ins and the token-anomaly family generally. This rule is narrower and deliberately
fires at **any** risk level, because the two risk types it reads are the ones where the risk rating understates the
event: a successful AiTM sign-in looks like a normal sign-in from a normal browser, and the proxy is only visible to
the risk engine. `attemptedPrtAccess` is the same family from the other end - something tried to read the Primary
Refresh Token, which is the credential an AiTM kit is after.

## Query

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 24 hours
| EVAL risks = TO_LOWER(MV_CONCAT(TO_STRING(azure.signinlogs.properties.risk_event_types_v2), ",")),
       usr = TO_LOWER(COALESCE(user.name, "")),
       app = TO_STRING(azure.signinlogs.properties.app_display_name),
       ip = TO_STRING(source.ip),
       asn = TO_STRING(source.as.organization.name),
       ua = TO_LOWER(COALESCE(TO_STRING(user_agent.original), "")),
       outcome = TO_STRING(azure.signinlogs.properties.status.error_code)
// the two risk types this rule exists for, whatever the risk level says
| WHERE risks LIKE "*attackerinthemiddle*" OR risks LIKE "*attemptedprtaccess*"
| STATS detections = COUNT(*),
        types = MV_SLICE(VALUES(risks), 0, 3),
        apps = MV_SLICE(VALUES(app), 0, 5),
        ips = MV_SLICE(VALUES(ip), 0, 5),
        asns = MV_SLICE(VALUES(asn), 0, 5),
        agents = MV_SLICE(VALUES(ua), 0, 3),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY usr
// Baseline: zero on an estate with no compromised users. This is a "one is an incident" rule - there is no
// threshold to tune, only a decision about whether the risk engine is trusted enough to page on.
| WHERE detections >= 1
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **Treat it as a live compromise, not a risk score.** The response in the same hour: revoke refresh tokens
  (`Revoke-MgUserSignInSession`), reset the password, and re-register MFA - the proxy holds a token that survives
  the first two on its own.
- **`asns` and `ips`** are the proxy's egress, not the user's. Both the attacker and the victim may appear in the
  same session, which is why the detection is not impossible travel.
- **`apps`** tells you what the stolen token can reach. A token for Exchange or SharePoint is mailbox and file
  access; a token for a first-party CLI is Graph enumeration (`S21`/`S29`).
- **`attemptedprtaccess` alone** is not always a compromise - but on a device that is not the user's, it is the
  device-code-to-PRT chain `S16`/`S17` describe.

## Nearest benign twins

- **A corporate TLS-inspecting proxy or CASB** that the risk engine mistakes for a reverse proxy. Rare, and it
  repeats for every user on that egress - a single user is not this.
- **A travel VPN or privacy service** flagged as anonymising. The risk type differs (`anonymizedIPAddress`), so it
  should not match here at all.

## What it misses

- **A phishing kit Microsoft has not seen.** The risk engine is the whole detection; a novel proxy is invisible.
  The behavioural fallback is `S08` (session reused across networks) and `S23` (refresh token from a
  never-interactive network), which need no risk licence.
- **On-premises compromise.** This is a cloud-token rule. Kerberos and NTLM theft is Defender for Identity's
  territory, and MDI's own alerts should be read alongside it.

## Test

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 30 days
| EVAL risks = TO_LOWER(MV_CONCAT(TO_STRING(azure.signinlogs.properties.risk_event_types_v2), ","))
| STATS events = COUNT(*) BY risks
| SORT events DESC
| LIMIT 20
```

If `risk_event_types_v2` is empty for every row, you have no Entra ID P2 (the licence these detections need) and
this rule cannot fire - fall back to `S08`/`S23`, which read the session itself.
