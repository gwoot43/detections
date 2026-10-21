---
id: D02
name: Sign-in attempt by a honey Entra user or honey service principal (any result)
category: deception
status: todo
rank: 1
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004, T1110.003, T1528, T1552.001]
data_source: Entra sign-in logs, all categories (interactive, non-interactive, service principal)
suppression:
  fields: [honey_identity, source.ip]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Honey identities have no owner. Two kinds are covered:
- **Honey users** synced from AD (D01) or cloud-only. Any sign-in attempt, successful or not, means someone has the UPN and is trying credentials. A failure with a wrong password (50126) still counts: it means the lure was read and tried. The failure codes tell you which lure: "user doesn't exist" (50034) means a UPN that was only ever written in a lure, and "account disabled" (50057) means a disabled honey account.
- **A honey service principal** whose client secret is planted in a decoy repo, config file, pipeline variable or Key Vault. Any token request for it means the secret was found. Red teams go after service principal credentials because they bypass MFA.

D01 sees the on-premises side. With password hash sync, an attacker trying honey credentials against Microsoft 365 never touches a DC, so this rule is the only one that sees it.

## Prerequisite
- Entra diagnostic settings must stream **SignInLogs**, **NonInteractiveUserSignInLogs** and **ServicePrincipalSignInLogs** to the Event Hub that Elastic reads. Service principal sign-ins are a separate category, and it's often left off.
- Replace the placeholder UPNs and app IDs in the deployed rule only. Don't commit real values. The honey service principal should have no API permissions, or harmless ones, so a stolen secret gets nothing useful.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| EVAL upn = TO_LOWER(COALESCE(azure.signinlogs.properties.user_principal_name, "")),
       app_id = TO_LOWER(COALESCE(azure.signinlogs.properties.app_id, "")),
       sp_id = TO_LOWER(COALESCE(azure.signinlogs.properties.service_principal_id, "")),
       // placeholders: UPNs and IDs in lowercase, because the fields are lowercased above
       honey_identity = CASE(
         upn IN ("<honey_upn_1>", "<honey_upn_2>", "<honey_upn_3>"), upn,
         azure.signinlogs.category == "ServicePrincipalSignInLogs"
           AND (app_id IN ("<honey_sp_app_id>") OR sp_id IN ("<honey_sp_object_id>")), CONCAT("sp:", app_id),
         NULL)
| WHERE honey_identity IS NOT NULL
| EVAL result = TO_STRING(azure.signinlogs.properties.status.error_code),
       outcome = CASE(result == "0", "SUCCESS", result == "50126", "wrong password", result == "50034", "user does not exist",
                      result == "50057", "account disabled", result IN ("50053", "50055"), "locked or expired",
                      result IN ("7000215", "7000222"), "invalid or expired client secret", CONCAT("error ", result))
| KEEP @timestamp, honey_identity, outcome, result, azure.signinlogs.category, source.ip, source.as.organization.name,
       source.geo.country_iso_code, azure.signinlogs.properties.app_display_name,
       azure.signinlogs.properties.resource_display_name, user_agent.original, _id, _version, _index
```
`outcome` reading **SUCCESS** is the worst case. For a user, it means the honey password itself leaked, or the account was reset. For the service principal, it means the planted secret works and the attacker now holds a token.

## Suppression
Suppress by `honey_identity`, `source.ip` for 1h. Alerts missing a key field are not suppressed. Sprays and token tools retry. A new source IP is a new alert.

## Known false positives / exclusions
- **Entra Connect provisioning** never signs in as the user, so it doesn't appear here.
- **Your own validation tests.** Run them from a known IP and close the alert.
- Microsoft's leaked-credential scanning doesn't sign in, so it can't cause an alert.

## Triage
- Identify where the attempt came from (`source.ip`, ASN, country, user agent), and block the IP at Conditional Access and Zscaler if it's external.
- Map the identity to its lure location in the restricted register. That tells you what the attacker read.
- **Service principal success:** revoke the secret, review the app's sign-ins and the audit log for anything it touched, and look for the same source IP on real accounts (S07, I07).

## Test
- **User:** sign in to `https://portal.office.com` with a honey UPN and a wrong password.
- **Service principal:** `az login --service-principal -u <app id> -p <planted secret> --tenant <tenant>` from a lab machine.
