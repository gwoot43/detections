---
id: S31
name: roadtx FOCI token exchange - one principal redeemed across several first-party public clients from a non-browser client
category: entra-signin-extended
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1550.001, T1528]
data_source: Entra ID sign-in logs (app id, client user agent, authentication protocol)
references: [https://github.com/dirkjanm/ROADtools]
suppression:
  fields: [user.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity

A stolen or phished refresh token is only as useful as the resources it can reach. Microsoft's **Family of Client IDs (FOCI)** is the lever: a refresh token issued to one first-party public client (Azure CLI, Azure PowerShell, Office, Teams, ...) can be redeemed for access tokens against **every other client in the family**. `roadtx` (ROADtools) automates exactly that redemption, so from the defender's side the signature is not any single sign-in but the **spread**: one principal receiving tokens for several of these public clients in a short window, from something that is not a browser.

This is the token-side companion to `S29` (ROADrecon's retired Graph audience) and the client-id twin of `S30` (roadtx token harvesting): `S30` anchors on the spread of **resource audiences** a session asks for - what the token is spent against - while this rule anchors on the spread of **FOCI client ids** - which first-party client identities one family refresh token is redeemed through. Different fields, the same walk seen from two sides; either can fire without the other. It does not need Entra ID P2 - it reads plain sign-in logs - and it keys on Microsoft's own well-known public client ids, which nothing in the estate should be walking across in bulk.

- **Anchor:** successful sign-ins for **three or more** FOCI public client ids under one principal in the window.
- **Corroborating property:** none of them came through a browser (`user_agent` not Mozilla-shaped). When the client is spoofed to look like a browser, the breadth of clients still carries it.
- **Exclusion:** developer workstations and automation that legitimately touch several first-party clients, allowlisted by `user.id` from the baseline.

## Query
Run every 15 minutes over the last hour.
```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 1 hour
| EVAL app = TO_LOWER(TO_STRING(azure.signinlogs.properties.app_id)),
       appname = TO_STRING(azure.signinlogs.properties.app_display_name),
       ua = TO_LOWER(COALESCE(TO_STRING(user_agent.original), "")),
       proto = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.authentication_protocol), "")),
       ip = TO_STRING(source.ip),
       outcome = TO_STRING(azure.signinlogs.properties.status.error_code)
// successful token issuance only - a failed redemption is not a usable session
| WHERE outcome == "0"
// the FOCI public clients a single family refresh token can be redeemed across. These are Microsoft's own
// well-known public client ids; the tell is one principal collecting tokens for several of them.
  AND app IN ("04b07795-8ddb-461a-bbee-02f9e1bf7b46",   // Azure CLI
              "1950a258-227b-4e31-a9cf-717495945fc2",   // Azure PowerShell
              "1b730954-1685-4b74-9bfd-dac224a7b894",   // Azure Active Directory PowerShell
              "d3590ed6-52b3-4102-aeff-aad2292ab01c",   // Microsoft Office
              "1fec8e78-bce4-4aaf-ab1b-5451cc387264",   // Microsoft Teams
              "29d9ed98-a469-4536-ade2-f981bc1d605e",   // Microsoft Authentication Broker
              "27922004-5251-4030-b22d-91ecd9a37ea4",   // Outlook Mobile
              "ab9b8c07-8f02-4f72-87fa-80105867a763")   // OneDrive sync
// a browser is a person signing in; the exchange tool is not one. When it spoofs a browser UA, the client
// breadth below still separates it.
  AND NOT ua LIKE "*mozilla*"
| STATS foci_apps = COUNT_DISTINCT(app),
        signins = COUNT(*),
        app_sample = MV_SLICE(VALUES(appname), 0, 8),
        agents = MV_SLICE(VALUES(ua), 0, 3),
        protocols = MV_SLICE(VALUES(proto), 0, 3),
        ips = MV_SLICE(VALUES(ip), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.id, user.name
// one principal receiving tokens for 3+ of these public clients in an hour, none through a browser, is the
// family-refresh-token walk. A real user and a single sanctioned script stay on one or two. Starting value;
// the baseline below is the source - it lists the estate's own multi-client principals to allowlist.
| WHERE foci_apps >= 3
| SORT foci_apps DESC
| LIMIT 50
```

## Reading the alert
- **`foci_apps`** is the signal: the count of distinct first-party public clients one principal was issued tokens for. Three is the starting line; a walk of five or six is unmistakable.
- **`agents`** names the caller. A Python / HTTP-library user agent is tooling; a real client presents its own product UA, and a browser never reaches this rule at all.
- **`protocols`** - a `deviceCode` protocol here is the device-code path a phished token often arrives through; worth noting even on its own.
- **`ips`** - one source address across the whole spread is one operator holding one token; several addresses can mean the token has been passed around.
- **`app_sample`** shows which clients were walked, which tells you what the token now reaches (Graph, ARM, Exchange, SharePoint).

## Before turning it on
- **Set the sanctioned list.** Run the baseline and allowlist, by `user.id`, the few principals that legitimately span several first-party clients - a developer who uses the Azure CLI and Azure PowerShell and Office from one box, or an automation account. Exclude the pair, never the whole tenant.
- Confirm the sign-in feed carries `app_id` and `user_agent` (the probe). If `user_agent` is unmapped, drop the Mozilla exclusion and raise `foci_apps` instead - the breadth anchor still works.

## Nearest benign twins
- **A developer workstation** using the Azure CLI and Azure PowerShell, and Office besides. Usually one or two FOCI clients, often with an interactive device-code the developer started themselves. If it genuinely spans three, it is an entity pair on `user.id`.
- **Automation / service principals** that touch several first-party clients on a schedule. Stable set, stable source - allowlist them.
- **MSAL token-cache refresh** in a rich client (Office, Teams) reuses that client's own id and does not fan out across the family, so it stays below the threshold.

## What it misses
- **A single-client token request** with no family walk - below the breadth threshold by design. `S29`, `S30` (the audience-spread half), the sign-in-risk detections and the conditional-access rules are the neighbours for the one-off case.
- **A spoofed browser user agent combined with only one or two clients** - the UA exclusion drops the browser-shaped caller, so a low-breadth, browser-spoofed request is invisible here.
- **PRT-cookie or device-registration abuse** that does not produce multiple FOCI sign-ins - that surfaces in the audit log (a device added, a credential registered) and the risk detections, not in this breadth count.
- **Redemptions against a different tenant** using a token minted here - this tenant's sign-in logs do not see them.

## Probe before enabling
```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 24 hours
| STATS signins = COUNT(*),
        with_app = COUNT(*) WHERE azure.signinlogs.properties.app_id IS NOT NULL,
        with_ua = COUNT(*) WHERE user_agent.original IS NOT NULL
```
`with_app` at zero means the sign-in pipeline is not carrying the client app id and this rule cannot anchor; `with_ua` at zero means the Mozilla exclusion is a no-op and should be removed with the threshold raised.

## Baseline
```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 30 days
| EVAL app = TO_LOWER(TO_STRING(azure.signinlogs.properties.app_id)),
       ua = TO_LOWER(COALESCE(TO_STRING(user_agent.original), ""))
| WHERE TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
  AND app IN ("04b07795-8ddb-461a-bbee-02f9e1bf7b46", "1950a258-227b-4e31-a9cf-717495945fc2",
              "1b730954-1685-4b74-9bfd-dac224a7b894", "d3590ed6-52b3-4102-aeff-aad2292ab01c",
              "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "29d9ed98-a469-4536-ade2-f981bc1d605e",
              "27922004-5251-4030-b22d-91ecd9a37ea4", "ab9b8c07-8f02-4f72-87fa-80105867a763")
  AND NOT ua LIKE "*mozilla*"
| STATS foci_apps = COUNT_DISTINCT(app), signins = COUNT(*) BY user.id, user.name
| SORT foci_apps DESC
| LIMIT 40
```
Every principal with a high `foci_apps` here is either sanctioned tooling (allowlist it) or already worth a look. The ones at one or two are the normal population the `>= 3` threshold sits above.

## Triage
- Treat a non-sanctioned principal with three or more FOCI clients as a **stolen-session** event, not a password problem: the response is to **revoke the refresh tokens** for that principal (and the sign-in sessions), not only reset the password - a reset does not invalidate an already-issued refresh token.
- Pull the same principal's recent audit-log activity: a device registered, a credential or app added, or a role change in the same window is the next stage and raises the severity.
- Map `app_sample` to what the token now reaches and check those resources (Graph reads, ARM changes, mailbox access) for what was done with it.

## References
- `rules/09-entra-signin-extended/S29-roadrecon-behavioural-aad-graph-audience.md` - the recon-side ROADtools rule; this is the token-side one
- `rules/09-entra-signin-extended/S30-roadtx-token-harvesting.md` - the audience-spread half of roadtx token harvesting; this is the client-id half
- ROADtools / roadtx (dirkjanm) - the token-exchange utility this models the telemetry of
- Microsoft identity platform - Family of Client IDs (FOCI) and first-party public client ids
- MITRE T1550.001 (application access token), T1528 (steal application access token)
