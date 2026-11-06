---
id: S30
name: roadtx token harvesting - one session asking for many resource audiences, and the rogue device registration behind it
category: entra-signin-extended
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1528, T1550.001, T1098.005]
data_source: Entra ID sign-in logs (resource audience, client, device) and audit log (device registration)
references: [https://unit42.paloaltonetworks.com/roadtools-cloud-attacks/, https://github.com/dirkjanm/ROADtools]
suppression:
  fields: [user.id, source.ip]
  duration: 1h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

`roadtx` does not exploit anything - it uses the authentication flows the tenant offers and takes the tokens. Unit 42
describes exactly that: device code flow, refresh-token reuse, on-behalf-of, and device registration, with the output
being "a set of OAuth 2.0 access and refresh tokens in JSON format" that the attacker then spends against cloud
services. Volexity's 2025 reporting on UTA0355 is the same pattern: a rogue device registered in Entra, then a token
with full Graph access.

Two properties make it visible without any tool signature.

**One.** A human, or a normal application, talks to **one or two resource audiences**. `roadtx gettokens` walks a
list - Microsoft Graph, the legacy AAD Graph, ARM, Exchange Online, Key Vault, Teams, Azure CLI - because the
attacker does not know yet which one will be useful. Many distinct audiences, one user, one address, one short
window, is token harvesting.

**Two.** The device code flow is not how a person signs in on a managed device, and roadtx's device registration is
not how a device joins. The audit record (`Register device`) from an address that has never registered a device,
after a device-code sign-in, is the chain Unit 42 describes.

`S21` reads Azure AD Graph activity logs, `S29` catches the retired AAD Graph audience, `S16`/`S17` cover the
device-code to WHfB chain. This rule covers the step before all of them: acquiring the tokens in the first place.

## Query

Run every 15 minutes with a 1-hour lookback.

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 1 hour
| EVAL usr = TO_LOWER(COALESCE(user.name, "")),
       ip = TO_STRING(source.ip),
       asn = TO_STRING(source.as.organization.name),
       res = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.resource_display_name),
                              TO_STRING(azure.signinlogs.properties.resource_id), "")),
       client = TO_STRING(azure.signinlogs.properties.client_app_display_name),
       ua = TO_LOWER(COALESCE(TO_STRING(user_agent.original), "")),
       managed = TO_LOWER(COALESCE(TO_STRING(device_detail.is_managed), "")),
       proto = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.authentication_protocol), "")),
       outcome = TO_STRING(azure.signinlogs.properties.status.error_code)
| WHERE outcome == "0" AND res != ""
// leading wildcard on purpose: browser user agents all carry "mozilla", and a human in a browser is the benign
// case this rule is trying to exclude. Everything else - python-requests, aiohttp, azcli, roadtools - is a client
// that can be scripted.
  AND NOT ua LIKE "*mozilla*"
| STATS resources = COUNT_DISTINCT(res, 1000),
        signins = COUNT(*),
        resource_sample = MV_SLICE(VALUES(res), 0, 8),
        clients = MV_SLICE(VALUES(client), 0, 5),
        agents = MV_SLICE(VALUES(ua), 0, 5),
        protocols = MV_SLICE(VALUES(proto), 0, 3),
        managed_flags = MV_SLICE(VALUES(managed), 0, 3),
        asns = MV_SLICE(VALUES(asn), 0, 3),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY usr, ip
// Baseline: a power user driving Azure CLI and Graph PowerShell side by side reaches three audiences in an hour.
// Four or more, from one address, non-browser, is a token sweep. Measure your own 95th percentile before lowering
// this; the resource list in the alert is what tells you which case you have.
| WHERE resources >= 4
| SORT resources DESC
| LIMIT 50
```

## The corroborating half: the rogue device

Run over 24 hours and read beside the alert above. This is the chain from the article - device code sign-in, then a
device registered in the tenant, then tokens used with that device's identity.

```esql
FROM logs-azure.signinlogs-*, logs-azure.auditlogs-*
// casts live in EVAL, not in the gate: the gate stays on plain fields so it can use the index
| EVAL stage = CASE(data_stream.dataset == "azure.signinlogs", "devicecode", "register"),
       outcome = COALESCE(TO_STRING(azure.signinlogs.properties.status.error_code), ""),
       proto = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.authentication_protocol), "")),
       op = COALESCE(TO_STRING(azure.auditlogs.operation_name), ""),
       ev_outcome = TO_LOWER(COALESCE(TO_STRING(event.outcome), ""))
// "Register device" is the user-initiated record; "Add device" is the service-written twin. Both are accepted
// because which one appears depends on the registration path - the probe at the end of this rule lists what your
// tenant actually writes.
| WHERE (stage == "devicecode" AND outcome == "0" AND proto == "devicecode")
     OR (stage == "register" AND ev_outcome == "success" AND op IN ("Register device", "Add device"))
| EVAL usr = TO_LOWER(COALESCE(azure.signinlogs.properties.user_principal_name,
                              azure.auditlogs.properties.initiated_by.user.userPrincipalName, "")),
       device_name = TO_LOWER(COALESCE(`azure.auditlogs.properties.target_resources.0.display_name`, "")),
       // assumed: the audit record's initiator address is not guaranteed on every pipeline - verify against a
       // known "Register device" row in Discover before relying on `ips` in the alert
       ip = TO_STRING(COALESCE(source.ip, azure.auditlogs.properties.initiated_by.user.ip_address))
| WHERE usr != ""
| STATS devicecode_at = MIN(CASE(stage == "devicecode", @timestamp, NULL)),
        register_at = MAX(CASE(stage == "register", @timestamp, NULL)),
        devices = MV_SLICE(VALUES(device_name), 0, 3),
        ips = MV_SLICE(VALUES(ip), 0, 3)
    BY usr
| WHERE devicecode_at IS NOT NULL AND register_at IS NOT NULL AND register_at >= devicecode_at
| SORT register_at DESC
| LIMIT 50
```

## Reading the alert

- **`resource_sample`** is the evidence. A sweep that includes the legacy AAD Graph audience
  (`00000002-0000-0000-c000-000000000000`) and Key Vault in the same hour is not a user doing their job.
- **`agents`** - `python-requests`, `aiohttp`, `roadtools` or an empty user agent is roadtx itself; `azcli` or
  `Microsoft-Graph-PowerShell` is the same technique with Microsoft's own clients, which is how an attacker avoids a
  strange user agent.
- **`managed_flags`** false or empty on every row means the session is on a device the tenant does not manage.
- **`devices`** in the second query: `DESKTOP-` followed by eight digits is roadtx's **default** device name (Unit 42
  documents the defaults, and they are easy to change). Treat a match as a strong hint, never as proof - a renamed
  device is the first thing a careful operator does.
- **After the tokens**: `S29` (retired AAD Graph audience), `S21` (enumeration volume, if the activity logs are on),
  and `S08`/`S23` for the session being replayed from a new network.

## Nearest benign twins

- **An automation or monitoring service principal** sweeping several Graph endpoints on a schedule. It authenticates
  as a **service principal**, not a user - if the alert has a `usr`, it is not this.
- **A cloud administrator** running `az login` plus `Connect-MgGraph` plus `Connect-ExchangeOnline` in one sitting.
  Three audiences, from a corporate address, on a managed device, and the same person does it weekly.
- **A backup or DLP product** reading Exchange and SharePoint with app-only permissions. No user context, and the
  `resources` count is stable over months.

## What it misses

- **A single-resource token theft.** An attacker who already knows what they want asks for one audience, and this
  rule never fires - that is `S08`/`S23` territory, or token protection if it is enabled.
- **A browser-shaped user agent.** The `NOT ua LIKE "*mozilla*"` filter is the evasion, and roadlib lets the
  operator set it.
- **Token use that never touches the sign-in log** - a refresh token replayed directly against a resource produces
  fewer sign-in records than a token request does. Graph activity logs are the only place that shows up.
- **Device registration by a guest or a BYOD enrolment policy** that legitimately allows it - allowlist by policy,
  not by user.

## Test

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 7 days
| EVAL usr = TO_LOWER(COALESCE(user.name, "")),
       res = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.resource_display_name), "")),
       ua = TO_LOWER(COALESCE(TO_STRING(user_agent.original), ""))
| WHERE TO_STRING(azure.signinlogs.properties.status.error_code) == "0" AND NOT ua LIKE "*mozilla*"
| STATS resources = COUNT_DISTINCT(res) BY usr
| SORT resources DESC
| LIMIT 20
```

This is the baseline and the false-positive check at once: whoever sits at four or more audiences over a week is
either your alert or your allowlist, and you will know which before you enable it.

Confirm the device-registration operation name your tenant writes - the second query depends on it:

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp >= NOW() - 90 days
  // leading wildcard on purpose: the audit category is "Device" or "Device registration" depending on the
  // record, and the point of this probe is to find out which
  AND azure.auditlogs.category LIKE "*device*"
| STATS events = COUNT(*) BY azure.auditlogs.operation_name
| SORT events DESC
| LIMIT 20
```

If this returns nothing at all, device registration is not in the audit log you collect, and the second query
cannot fire - the first query still works, and `S17` covers the same chain from the sign-in side.
