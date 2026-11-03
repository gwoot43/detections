# OAuth and application probing from one source (identity-provider reconnaissance)

Unit42's Stage 3 for ARTEX is identity probing rather than credential guessing: **more than 700 denied attempts** against internal applications behind a cloud identity-aware proxy, `illegal_redirect_uri_enhanced` rejections from an authorisation request aimed at an external test domain, password spray, and password-reset / OTP / MFA-profile endpoints probed on consumer identity services — with **no successful account compromise observed**. Stage 4 then begins **two minutes** after the last failed authorisation, when the agent gives up on identity and pivots to the API surface.

That shape is visible in Entra sign-in logs, and it is different from what the library already owns. `S13`, `S14` and `S15` count failures **per user** — a spray. This counts failures **per source across many applications**, with the error codes that mean *the client is wrong*, not *the password is wrong*:

- **50011** — redirect URI mismatch: the reply URL is not registered on the app.
- **700016** — the application does not exist in the tenant.
- **65001** — consent or authorisation not granted for the requested scope.

An agent harvesting OAuth flows and app registrations produces these by construction; a credential spray produces `50126` (invalid credentials) instead, which is why the two rules do not overlap.

```esql
FROM logs-azure.signinlogs-*
// One hour in the query: a probing run is minutes long, and the counts are per source.
| WHERE @timestamp >= NOW() - 1 hour
| EVAL app = TO_LOWER(TO_STRING(azure.signinlogs.properties.app_id)),
       ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       ip = TO_STRING(source.ip)
// Client-configuration errors, not credential errors.
| EVAL probe_error = ec IN ("50011", "700016", "65001"),
       succeeded = ec == "0"
| STATS attempts = COUNT(*),
        probe_failures = COUNT(*) WHERE probe_error,
        apps = COUNT_DISTINCT(app),
        resources = COUNT_DISTINCT(azure.signinlogs.properties.resource_display_name),
        users = COUNT_DISTINCT(azure.signinlogs.properties.user_principal_name),
        success = COUNT(*) WHERE succeeded,
        codes = MV_SLICE(VALUES(ec), 0, 6),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY ip
// Many failures against several applications with nothing working. 25 / 3 / zero are starting values - a
// legitimate broken client retries one app, and an estate with many custom apps raises the app floor rather
// than the volume one. The baseline at the foot of this file is the source that sets them.
| WHERE probe_failures >= 25 AND apps >= 3 AND success == 0
| SORT probe_failures DESC
| LIMIT 50
```

Deploy every 15 minutes over the last hour. Suppress by `ip` for 6h.

## Reading the alert
- **`apps`** is the discriminator: three or more distinct applications from one address means enumeration, because a misconfigured client sticks to its own registration.
- **`codes`** names the technique. `50011` alone is app-registration hunting; `700016` means the client is guessing app IDs that do not exist here; a mix with `65001` is consent-flow probing.
- **`success == 0`** is required, not cosmetic: a real integration that fails first and succeeds later is not this.
- **`users`** near `attempts` means one attempt per identity (discovery); `users` of 1-2 with many attempts means one account being worked, which is the brute-force rules' territory.
- **`last_seen`** matters operationally: Stage 4 starts about two minutes after the final failure, so the API-side activity is already under way by the time this is read.

## Nearest benign twins
- **A developer integrating a new application** against the tenant: `50011` and `65001` repeatedly, from one source — but one app, one user, and it usually ends in a success. The `apps >= 3` and `success == 0` conditions remove it.
- **A misconfigured service principal or sync client** retrying on a schedule: many failures, one app, and a stable cadence across days. Entity pair on the app ID.
- **Penetration testers** enumerating the tenant's app registrations: this is exactly the behaviour, so it should alert. Scope by tester address for the engagement window.
- **Legacy clients** that always fail `65001` because consent was never granted: one app, one user, every day. An entity pair after the first week.

## What it misses
- **A probe that guesses usernames and passwords** rather than apps — `S15` covers it, and the two should be read together when both fire from one address.
- **Service-principal-only enumeration** (client-credential flows) that never produces an interactive sign-in error, and the Graph/AzureRM discovery that follows a successful token — `S21` is the network-side view of that.
- **The application side of Stage 5**: self-registration followed by bulk reads, and write-then-read-back on an API. Those live in the web application's logs, not in the IdP.
- **Probing against a different identity provider** (an external IdP or a SaaS tenant that federates elsewhere) — nothing here sees it.

## Baseline
```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 30 days
| EVAL ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       ip = TO_STRING(source.ip),
       app = TO_LOWER(TO_STRING(azure.signinlogs.properties.app_id))
| WHERE ec IN ("50011", "700016", "65001")
| STATS failures = COUNT(*), apps = COUNT_DISTINCT(app) BY ip
| SORT failures DESC
| LIMIT 40
```
The top rows are the estate's own broken clients and integration tooling. Anything that later appears with a new address, several apps and no successes is the population this rule alerts on.

## References
- Unit42, *Activity using ARTEX agentic AI framework* (30 Oct 2026) - 700+ denied identity-aware-proxy attempts, `illegal_redirect_uri_enhanced` rejections, reset/OTP/MFA probing, no successful IdP compromise, and the two-minute pivot to API surface: `github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-10-30-activity-using-ARTEX-agentic-AI.txt`
- `rules/09-entra-signin-extended/S13`, `S14`, `S15` - the per-user failure rules this complements rather than duplicates
- `rules/09-entra-signin-extended/S21` - Graph enumeration after a successful token
- MITRE T1589.002 / T1598 (identity information gathering and phishing), T1110 (brute force) as the neighbouring technique
