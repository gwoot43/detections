---
id: S28
name: Token issuer anomaly - a SAML token from an unexpected issuer (Golden SAML), with the federation change behind it
category: entra-signin-extended
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1606.002, T1558.001, T1078.004]
data_source: Entra ID Protection tokenIssuerAnomaly risk detection, plus the Entra audit log federation change
references: [https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks]
suppression:
  fields: [user.id]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

**Token issuer anomaly** is a specific claim: the SAML token presented for this sign-in was issued by something
that is not a trusted issuer, or its claims match known attacker patterns. That is Golden SAML - the attacker signs
their own assertions with a stolen token-signing certificate and can then be any user, in any app, without a
password or MFA.

It is the one cloud detection where the *cause* is also logged. To forge assertions the attacker has to trust their
own issuer, which means a federation setting was changed on the domain - or the signing certificate was rolled. The
pair is close to conclusive: a token issuer anomaly with a federation change inside the same window is not a false
positive.

`I07` reads this risk type as one of several; here it is the anchor, and the rule is built to be read with the audit
trail beside it.

## Query

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 24 hours
| EVAL risks = TO_LOWER(MV_CONCAT(TO_STRING(azure.signinlogs.properties.risk_event_types_v2), ",")),
       usr = TO_LOWER(COALESCE(user.name, "")),
       app = TO_STRING(azure.signinlogs.properties.app_display_name),
       res = TO_STRING(azure.signinlogs.properties.resource_display_name),
       ip = TO_STRING(source.ip),
       asn = TO_STRING(source.as.organization.name),
       outcome = TO_STRING(azure.signinlogs.properties.status.error_code)
// the issuer anomaly itself. Not filtered by risk level: the token already authenticated.
| WHERE risks LIKE "*tokenissueranomaly*"
| STATS signins = COUNT(*),
        apps = MV_SLICE(VALUES(app), 0, 5),
        resources = MV_SLICE(VALUES(res), 0, 5),
        ips = MV_SLICE(VALUES(ip), 0, 5),
        asns = MV_SLICE(VALUES(asn), 0, 5),
        outcomes = MV_SLICE(VALUES(outcome), 0, 3),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY usr
// Baseline: zero. A forged assertion is not a volume event - one successful sign-in is the incident.
| WHERE signins >= 1
| SORT first_seen DESC
| LIMIT 50
```

The corroborating half, to run over the same window and join by hand (or in a dashboard):

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp >= NOW() - 7 days
// leading wildcard on purpose: the operation name for a federation change varies by how it was made
// (portal, Graph, AADInternals), and every variant contains the word
  AND azure.auditlogs.operation_name LIKE "*federation*"
| EVAL actor = TO_LOWER(COALESCE(TO_STRING(azure.auditlogs.properties.initiated_by.user.userPrincipalName), "")),
       target = TO_LOWER(COALESCE(TO_STRING(MV_FIRST(azure.auditlogs.properties.target_resources.display_name)), "")),
       op = TO_STRING(azure.auditlogs.operation_name),
       result = TO_LOWER(COALESCE(TO_STRING(azure.auditlogs.result), ""))
| STATS changes = COUNT(*), ops = MV_SLICE(VALUES(op), 0, 3), results = MV_SLICE(VALUES(result), 0, 3),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY actor, target
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **A federation change plus an issuer anomaly is Golden SAML in progress.** Revoke the trust, roll the
  token-signing certificate, and treat every sign-in in the window as attacker-controlled.
- **The issuer anomaly without a change** means the signing key was stolen rather than replaced - the certificate is
  still trusted, so the trust itself looks correct. Rolling it is still the response.
- **`outcomes` non-zero** is a failed forgery: the claim shape was wrong. Still an incident - someone has a key.
- **Which app.** A token for Exchange Online is mailbox access; for Azure management it is the subscription.

## Nearest benign twins

- **A legitimate federation migration** (moving from ADFS to managed, or a new IdP during a merger) - change
  ticketed, and it produces the audit event *without* the risk detection.
- **A third-party SAML app** with unusual claim formatting. Rare, and it repeats for every user of that app rather
  than for one account.

## What it misses

- **Golden SAML that the risk engine does not flag** - a well-formed assertion from a stolen key can look normal.
  The federation-change half is the safety net, which is why both queries are in this rule.
- **Token-signing certificate theft without a trust change.** Only the anomaly catches it, and only if Microsoft's
  model dislikes the claims.
- **On-premises Golden Ticket** (krbtgt, not SAML). That is `AD08` and Defender for Identity.

## Test

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp >= NOW() - 30 days
| STATS events = COUNT(*) BY azure.auditlogs.operation_name
| SORT events DESC
| LIMIT 40
```

Use this to confirm the exact federation operation name in your tenant before relying on the `LIKE "*federation*"`
filter, and to see whether federation is even configured - a cloud-only tenant with no federation has nothing to
forge here, and the rule is then only about token-signing certificates.
