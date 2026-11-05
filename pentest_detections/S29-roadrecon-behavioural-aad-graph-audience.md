---
id: S29
name: ROADrecon behaviour - a token for the retired Azure AD Graph audience from a non-browser client
category: entra-signin-extended
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1087.004, T1526, T1550.001]
data_source: Entra ID sign-in logs (resource audience, client and user agent)
references: [https://github.com/dirkjanm/ROADtools]
suppression:
  fields: [user.id]
  duration: 1h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

`S21` reads Azure AD Graph **activity logs**, which are not collected by default - so in most estates that rule is
silent whether or not anyone is enumerating. This is the behavioural version, built only on the sign-in log you
already have.

The anchor is the audience. ROADrecon's `gather` refuses to run unless its token is for
`https://graph.windows.net` (resource id `00000002-0000-0000-c000-000000000000`) - it checks the audience in the
source code. Azure AD Graph is retired for new use, and everything current asks for Microsoft Graph
(`00000003-...`) instead. So a token being issued for the **legacy** audience, to a **non-browser** client, is
either an ancient internal tool you can name, or ROADtools.

`roadrecon auth` also offers a device-code flow, which shows as `authentication_protocol == "devicecode"` - a
legitimate pattern, but not one that then asks for the retired audience.

## Query

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 24 hours
| EVAL resid = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.resource_id), "")),
       res = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.resource_display_name), "")),
       client = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.client_app_display_name), "")),
       ua = TO_LOWER(COALESCE(TO_STRING(user_agent.original), "")),
       proto = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.authentication_protocol), "")),
       ip = TO_STRING(source.ip),
       outcome = TO_STRING(azure.signinlogs.properties.status.error_code)
| WHERE outcome == "0"
// the retired Azure AD Graph audience - resource id first, display name as the fallback for pipelines that drop it
  AND (resid == "00000002-0000-0000-c000-000000000000" OR res LIKE "*windows azure active directory*")
// non-browser clients only: a browser hitting the legacy endpoint is a stale bookmark, not a collector
  AND NOT ua LIKE "*mozilla*"
| STATS signins = COUNT(*),
        clients = MV_SLICE(VALUES(client), 0, 5),
        agents = MV_SLICE(VALUES(ua), 0, 5),
        protocols = MV_SLICE(VALUES(proto), 0, 3),
        ips = MV_SLICE(VALUES(ip), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.id, user.name
// Baseline: zero once legacy tooling is migrated. Allowlist by client app id, never by user - a collector uses
// whichever account it phished, so the account is the variable and the client is the constant.
| WHERE signins >= 1
| SORT signins DESC
| LIMIT 50
```

## Reading the alert

- **`agents`** is the tell. `aiohttp`, `python-requests` or `roadtools` in the user agent is ROADrecon itself;
  `Microsoft Office` or a named internal app is the legacy case the allowlist is for.
- **`protocols`** containing `devicecode` means the collector authenticated by device code - the phishing-friendly
  path `S16` describes, and worth reading with it.
- **One account, several clients** is a dump in progress; the token is being reused across tools.
- **After the token**: `S21` (if AAD Graph activity logs are on) or Microsoft Graph activity logs for the
  enumeration volume. Without either, this rule tells you the collector authenticated, not what it read.

## Nearest benign twins

- **A legacy internal application** still coded against AAD Graph. It authenticates as its own service principal,
  on a schedule, from one address - allowlist by app id after confirming with the owner.
- **PowerShell `AzureAD` module** (the old one, not `Microsoft.Graph`). Same audience, and it is worth migrating
  rather than allowlisting - it is exactly the credential path ROADrecon abuses.

## What it misses

- **ROADtools moved to Microsoft Graph.** `roadrecon` can be pointed at Graph; then the audience is normal and this
  rule is blind. `S21`'s endpoint-breadth logic is the answer, and it needs the activity logs.
- **A collector using a browser-like user agent** - the `NOT ua LIKE "*mozilla*"` filter is the evasion, and it is
  the first thing a careful operator changes.
- **A dump with no sign-in at all** (a stolen refresh token). That is `S23`.

## Test

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 30 days
| EVAL resid = TO_LOWER(COALESCE(TO_STRING(azure.signinlogs.properties.resource_id), ""))
| STATS signins = COUNT(*) BY resid
| SORT signins DESC
| LIMIT 20
```

Confirm `resource_id` is populated and see whether `00000002-0000-0000-c000-000000000000` appears at all. If the
field is empty, switch the filter to `resource_display_name` alone - the rule still works, it just needs the name.
