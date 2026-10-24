---
id: CS17
name: Secret scanner on a host - one process tests keys against several unrelated providers (TruffleHog, Shai-Hulud, stealers)
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1552.001, T1083]
data_source: CrowdStrike FDR DnsRequest; Zscaler ZIA web logs as a second source
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
**One question:** is a program on this host testing stolen keys? The Shai-Hulud npm worm (2025, with variants through 2026) runs TruffleHog on every developer machine it infects, and TruffleHog checks each key it finds against the provider that issued it. Infostealers do the same. Scanning a disk leaves nothing in FDR, which doesn't record file reads, but the checking does: one process looks up the key-checking endpoints of several unrelated providers in a short time. Real tools talk to one provider (`gh` to GitHub, `aws` to AWS). This works whatever the program is called.

- **Anchor:** lookups of the endpoints a program calls to test a key, one per provider: AWS's identity service (STS), GitHub's API, npm's registry, the AI, payment, monitoring, mail, SMS and hosting APIs.
- **Corroborating property:** several unrelated providers from one process within the window. GitHub, npm, AWS STS and the AI APIs are what developer tools call all day; mail, SMS and hosting APIs (SendGrid, Twilio, Mailgun, Heroku, DigitalOcean) rarely show up on a developer's machine. So it takes four providers, or three with at least one rare one.
- **Exclusion:** code editors and browsers, which call these APIs for their own reasons (Copilot, AI extensions, AWS Toolkit, Stripe.js), and the scanner CI runners and AppSec hosts run by design, as host + process pairs.

A package runtime as the tester (`node`, `bun`, `deno`, `python`) is the worm testing what it found; `ContextBaseFileName` (`process.name` in ES|QL) is in the output for scoring.

There's no filename fallback here. Known attacker tools by name, TruffleHog included, are CS18's job.

## Query
**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run every 15 minutes over the last 20 minutes:
```logscale
#event_simpleName=DnsRequest
// 1 GATE: the endpoints a program calls to test a key, one per provider, by an anchored regex on the raw name (any
// case, optional trailing dot). DNS is the busiest event, so this runs before anything else; then the grouping key.
| DomainName=/^(sts(-fips)?(\.[a-z0-9-]+)?\.amazonaws\.com|api\.github\.com|registry\.npmjs\.org|api\.(openai|anthropic|stripe|cloudflare|sendgrid|twilio|heroku|digitalocean)\.com|api\.mailgun\.net|api\.datadoghq\.(com|eu))\.?$/i
| aid=* ContextProcessId=*
// 2 SHAPE: the provider is the name's second-to-last label (so Datadog's US and EU APIs are one provider), lowercased
// into a new field; rare is set only for the mail, SMS and hosting APIs.
| regex("(?<provider>[^.]+)\.[^.]+\.?$", field=DomainName)
| provider := lower(provider)
| regex("^(?<rare>sendgrid|twilio|mailgun|heroku|digitalocean)$", field=provider, strict=false)
// 3 REDUCE: one row per process: the providers it tested in the window. The search window is the burst window,
// so keep it short (15-30 min) with the schedule matching; a long window lets busy processes accumulate providers.
| groupBy([aid, ContextProcessId], function=[count(provider, distinct=true, as=providers), count(rare, distinct=true, as=rare_providers),
                                             min(@timestamp, as=first_seen), collect([ComputerName, ContextBaseFileName, provider])],
          limit=max)
// 4 DECIDE: four or more providers, or three with at least one rare one. Starting values; set them from the
// baseline query (run separately over 30 days).
// Deliberately no * branch: an event passes if any branch matches.
| case { test(providers >= 4); test(providers >= 3) | test(rare_providers >= 1); }
// 5 ENRICH, on the survivors only. Drop code editors and browsers; a process with no name on its DNS events stays in.
| NOT ContextBaseFileName=/^(code|code - insiders|cursor|windsurf|chrome|msedge|firefox|brave)(\.exe)?$/i
// Scanners CI runners and AppSec hosts run by design: one line per host and process (placeholders).
| NOT (aid="<ci_runner_aid>" AND ContextBaseFileName=/^<scanner_process>$/i)
| NOT (aid="<appsec_aid>" AND ContextBaseFileName=/^<scanner_process>$/i)
// Host name from the sensor inventory, in case DNS events don't carry ComputerName.
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
// 6 OUTPUT
| first_seen := formatTime("%Y-%m-%d %H:%M:%S", field=first_seen, timezone="Australia/Sydney")
| select([aid, ComputerName, ContextBaseFileName, ContextProcessId, providers, rare_providers, provider, first_seen])
```

**Same detection in ES|QL**, run every 15 minutes with a 20-minute lookback:
```esql
FROM logs-yourorg-crowdstrike-data-default*
// 1 GATE: lookups of the endpoints a program calls to test a key, one per provider. Prefix matches, which the index
// answers (and which also match the trailing dot some names carry), so the rest of DNS is never read. The grouping key
// must be present.
| WHERE event.action == "dnsrequest" AND host.id IS NOT NULL AND data.ContextProcessId IS NOT NULL
  AND (data.DomainName LIKE "sts*.amazonaws.com*" OR data.DomainName LIKE "api.github.com*"
       OR data.DomainName LIKE "registry.npmjs.org*" OR data.DomainName LIKE "api.openai.com*"
       OR data.DomainName LIKE "api.anthropic.com*" OR data.DomainName LIKE "api.stripe.com*"
       OR data.DomainName LIKE "api.cloudflare.com*" OR data.DomainName LIKE "api.datadoghq.com*"
       OR data.DomainName LIKE "api.datadoghq.eu*" OR data.DomainName LIKE "api.sendgrid.com*"
       OR data.DomainName LIKE "api.twilio.com*" OR data.DomainName LIKE "api.mailgun.net*"
       OR data.DomainName LIKE "api.heroku.com*" OR data.DomainName LIKE "api.digitalocean.com*")
// 2 SHAPE: the provider each lookup tests. Datadog's US and EU APIs are one provider.
| EVAL provider = CASE(data.DomainName LIKE "sts*", "aws", data.DomainName LIKE "api.github*", "github",
                       data.DomainName LIKE "registry.npmjs*", "npm", data.DomainName LIKE "api.openai*", "openai",
                       data.DomainName LIKE "api.anthropic*", "anthropic", data.DomainName LIKE "api.stripe*", "stripe",
                       data.DomainName LIKE "api.cloudflare*", "cloudflare", data.DomainName LIKE "api.datadoghq*", "datadog",
                       data.DomainName LIKE "api.sendgrid*", "sendgrid", data.DomainName LIKE "api.twilio*", "twilio",
                       data.DomainName LIKE "api.mailgun*", "mailgun", data.DomainName LIKE "api.heroku*", "heroku",
                       data.DomainName LIKE "api.digitalocean*", "digitalocean", NULL)
// 3 REDUCE: one row per process: the providers it tested in the window (the schedule is the window).
| STATS providers = COUNT_DISTINCT(provider),
        rare_providers = COUNT_DISTINCT(provider) WHERE provider IN ("sendgrid", "twilio", "mailgun", "heroku", "digitalocean"),
        tested = VALUES(provider), process.name = VALUES(data.ContextBaseFileName), host.name = VALUES(host.name),
        first_seen = MIN(@timestamp)
    BY host.id, data.ContextProcessId
// 4 DECIDE: four or more providers, or three with at least one rare one. Starting values; set them from the
// baseline query (run separately over 30 days).
| WHERE providers >= 4 OR (providers >= 3 AND rare_providers >= 1)
// 5 ENRICH, on the survivors only. A process whose DNS events carry no name reads "unknown" and stays in. Drop code
// editors and browsers, and the scanner CI runners and AppSec hosts run by design (host + process; placeholders).
| EVAL process.name = COALESCE(MV_MIN(process.name), "unknown")
| WHERE NOT TO_LOWER(process.name) RLIKE "(code|code - insiders|cursor|windsurf|chrome|msedge|firefox|brave)(\\.exe)?"
  AND NOT (host.id IN ("<ci_runner_aid>", "<appsec_aid>") AND process.name == "<scanner_process>")
// 6 OUTPUT: the host, the process and what it tested. first_seen is UTC (ES|QL dates are). The pivot query names the
// program and its command line.
| KEEP host.id, host.name, process.name, data.ContextProcessId, providers, rare_providers, tested, first_seen
```
The host name comes from the events here. LogScale takes it from the sensor inventory (`aid_master_main.csv`) because DNS events may not carry `ComputerName`.

## Second source: Zscaler web logs
The checks are HTTPS calls, so they also pass through Zscaler, which sees two things the endpoint can't:
- **TruffleHog's user agent.** I believe TruffleHog's checks identify themselves with a `TruffleHog` user agent, on whatever provider they go to, not just the ones on the list. It's visible only where Zscaler inspects TLS for that traffic; confirm both with the Test below before relying on it.
- **The same burst, without the endpoint's limits.** Linux machines whose lookups aren't credited to the program, endpoints using an explicit proxy, and devices without Falcon all still send the calls through Zscaler. Zscaler has no process, so the burst is counted per device and user, leaving out browsers and editors by their user agent.

Run every 15 minutes with a 20-minute lookback, as its own rule:
```esql
FROM logs-zscaler_zia.web-*
// 1 GATE: calls to the key-checking endpoints, or anything sent with TruffleHog's user agent. Exact hosts and prefix
// matches, which the index answers, so the rest of the web traffic is never read. Every row must carry its device.
| WHERE (url.domain IN ("api.github.com", "registry.npmjs.org", "api.openai.com", "api.anthropic.com", "api.stripe.com",
                        "api.cloudflare.com", "api.datadoghq.com", "api.datadoghq.eu", "api.sendgrid.com", "api.twilio.com",
                        "api.mailgun.net", "api.heroku.com", "api.digitalocean.com")
         OR url.domain LIKE "sts*.amazonaws.com" OR user_agent.original LIKE "TruffleHog*")
  AND source.ip IS NOT NULL
// 2 SHAPE: the provider each call tests (none for a TruffleHog call to another host), and the user, which servers and
// CI runners often don't have.
| EVAL provider = CASE(url.domain LIKE "sts*.amazonaws.com", "aws", url.domain == "api.github.com", "github", url.domain == "registry.npmjs.org", "npm",
                       url.domain == "api.openai.com", "openai", url.domain == "api.anthropic.com", "anthropic",
                       url.domain == "api.stripe.com", "stripe", url.domain == "api.cloudflare.com", "cloudflare",
                       url.domain LIKE "api.datadoghq*", "datadog", url.domain == "api.sendgrid.com", "sendgrid",
                       url.domain == "api.twilio.com", "twilio", url.domain == "api.mailgun.net", "mailgun",
                       url.domain == "api.heroku.com", "heroku", url.domain == "api.digitalocean.com", "digitalocean", NULL),
       user = COALESCE(user.name, "unauthenticated")
// 3 REDUCE: one row per device and user. Providers are counted only from programs, not browsers or editors (their user
// agents start "Mozilla/"); a call with no user agent (TLS not inspected) counts.
| STATS providers = COUNT_DISTINCT(provider) WHERE user_agent.original IS NULL OR NOT user_agent.original LIKE "Mozilla/*",
        rare_providers = COUNT_DISTINCT(provider) WHERE provider IN ("sendgrid", "twilio", "mailgun", "heroku", "digitalocean")
          AND (user_agent.original IS NULL OR NOT user_agent.original LIKE "Mozilla/*"),
        trufflehog_calls = COUNT(*) WHERE user_agent.original LIKE "TruffleHog*",
        tested = VALUES(provider), hosts_called = COUNT_DISTINCT(url.domain), sample_hosts = TOP(url.domain, 10, "asc"),
        user_agents = TOP(user_agent.original, 5, "asc"), first_seen = MIN(@timestamp)
    BY source.ip, user
// 4 DECIDE: TruffleHog's own user agent, or the same burst as the endpoint rule. Thresholds: the endpoint rule's
// starting values, not yet baselined; baseline them the same way, grouped by source.ip and user.
| EVAL finding = CASE(trufflehog_calls > 0, "trufflehog_user_agent",
                      providers >= 4 OR (providers >= 3 AND rare_providers >= 1), "keys_tested", NULL)
| WHERE finding IS NOT NULL
// 5 ENRICH: a CI runner or AppSec host and the account its scanner runs as, never the whole address (placeholders).
| WHERE NOT (CIDR_MATCH(source.ip, "198.51.100.10/32") AND user == "<ci_scanner_account>")
// 6 OUTPUT: the device and user, what was tested and how it identified itself.
| KEEP source.ip, user, finding, providers, rare_providers, trufflehog_calls, tested, hosts_called, sample_hosts, user_agents,
       first_seen
```
Suppress by `source.ip`, `user`, `finding` for 24h. There's no LogScale version: the Zscaler logs are in Elastic. Find the device behind `source.ip` (Zscaler Client Connector or DHCP), then run the endpoint pivot query there for the process.

## Rule settings
| | |
|---|---|
| Interval / lookback | 15 minutes / 20 minutes. The schedule is the window; the five extra minutes absorb ingest lag. Keep the window short (15-30 minutes): a longer one lets busy processes add up providers. |
| Suppression | `host.id` (`aid`) for 24h |
| Zscaler query | 15 minutes / 20 minutes; suppress by `source.ip`, `user`, `finding` for 24h |

## Telemetry assumptions
- `dnsrequest` events with Falcon's raw fields `data.DomainName` (may end in a dot) and `data.ContextProcessId`. The rule doesn't use ECS `dns.question.*`.
- **The process name on DNS events** (`data.ContextBaseFileName`). The editor exclusion and the CI pairs depend on it. Where it's missing, editors aren't dropped (more noise) and the pairs can't match; the pivot query still names the program.
- **Which process the lookup is charged to.** On Windows, it's the program that asked. TruffleHog is written in Go, and Go's resolver on Linux can send DNS itself, so on Linux (CI runners in particular) test it before trusting it (see Test).

- **Zscaler:** `url.domain` and `user_agent.original` on web logs. The user agent is only there where Zscaler inspects TLS; `zscaler_zia.web.ssl_decrypted` says which. `source.ip` is the device's own address when Zscaler Client Connector forwards it; behind an office tunnel without it, many users share one address, and the burst adds up across them.

Confirm the names and process IDs reach your DNS events, over the last day (the gate keeps this small):
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "dnsrequest"
  AND (data.DomainName LIKE "api.github.com*" OR data.DomainName LIKE "registry.npmjs.org*")
| STATS lookups = COUNT(*), with_pid = COUNT(data.ContextProcessId), with_name = COUNT(data.ContextBaseFileName)
    BY data.event_platform
```
```logscale
#event_simpleName=DnsRequest DomainName=/^(api\.github\.com|registry\.npmjs\.org)\.?$/i
| groupBy([event_platform], function=[count(as=lookups), count(ContextProcessId, as=with_pid), count(ContextBaseFileName, as=with_name)],
          limit=max)
```

For the Zscaler query, check over the last day how much of this traffic is inspected and carries a user agent:
```esql
FROM logs-zscaler_zia.web-*
| WHERE url.domain IN ("api.github.com", "registry.npmjs.org")
| STATS requests = COUNT(*), devices = COUNT_DISTINCT(source.ip), with_user_agent = COUNT(user_agent.original),
        inspected = COUNT(*) WHERE zscaler_zia.web.ssl_decrypted == "Yes"
    BY url.domain
```

## Baseline and threshold source
The gate keeps only a few lookups, so this is cheap enough to run over 30 days at once. It rebuilds the rule's window as 15-minute buckets and measures how many providers one process reaches in a window:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "dnsrequest" AND host.id IS NOT NULL AND data.ContextProcessId IS NOT NULL
  AND (data.DomainName LIKE "sts*.amazonaws.com*" OR data.DomainName LIKE "api.github.com*"
       OR data.DomainName LIKE "registry.npmjs.org*" OR data.DomainName LIKE "api.openai.com*"
       OR data.DomainName LIKE "api.anthropic.com*" OR data.DomainName LIKE "api.stripe.com*"
       OR data.DomainName LIKE "api.cloudflare.com*" OR data.DomainName LIKE "api.datadoghq.com*"
       OR data.DomainName LIKE "api.datadoghq.eu*" OR data.DomainName LIKE "api.sendgrid.com*"
       OR data.DomainName LIKE "api.twilio.com*" OR data.DomainName LIKE "api.mailgun.net*"
       OR data.DomainName LIKE "api.heroku.com*" OR data.DomainName LIKE "api.digitalocean.com*")
// The rule's 15-minute window, rebuilt as a bucket so 30 days can be measured in one search.
| EVAL provider = CASE(data.DomainName LIKE "sts*", "aws", data.DomainName LIKE "api.github*", "github",
                       data.DomainName LIKE "registry.npmjs*", "npm", data.DomainName LIKE "api.openai*", "openai",
                       data.DomainName LIKE "api.anthropic*", "anthropic", data.DomainName LIKE "api.stripe*", "stripe",
                       data.DomainName LIKE "api.cloudflare*", "cloudflare", data.DomainName LIKE "api.datadoghq*", "datadog",
                       data.DomainName LIKE "api.sendgrid*", "sendgrid", data.DomainName LIKE "api.twilio*", "twilio",
                       data.DomainName LIKE "api.mailgun*", "mailgun", data.DomainName LIKE "api.heroku*", "heroku",
                       data.DomainName LIKE "api.digitalocean*", "digitalocean", NULL),
       win = DATE_TRUNC(15 minutes, @timestamp)
| STATS providers = COUNT_DISTINCT(provider),
        rare_providers = COUNT_DISTINCT(provider) WHERE provider IN ("sendgrid", "twilio", "mailgun", "heroku", "digitalocean"),
        process.name = VALUES(data.ContextBaseFileName)
    BY host.id, data.ContextProcessId, win
| EVAL process.name = COALESCE(MV_MIN(process.name), "unknown")
// Second STATS, baseline only: the distribution across windows. For top talkers instead, replace this STATS with:
//   STATS peak_providers = MAX(providers), peak_rare = MAX(rare_providers), windows = COUNT(*) BY host.id, process.name
//   | SORT peak_providers DESC | LIMIT 50
| STATS windows = COUNT(*), p50 = PERCENTILE(providers, 50), p95 = PERCENTILE(providers, 95), p99 = PERCENTILE(providers, 99),
        max = MAX(providers), windows_with_rare = COUNT(*) WHERE rare_providers >= 1
```
```logscale
#event_simpleName=DnsRequest
| DomainName=/^(sts(-fips)?(\.[a-z0-9-]+)?\.amazonaws\.com|api\.github\.com|registry\.npmjs\.org|api\.(openai|anthropic|stripe|cloudflare|sendgrid|twilio|heroku|digitalocean)\.com|api\.mailgun\.net|api\.datadoghq\.(com|eu))\.?$/i
| aid=* ContextProcessId=*
| regex("(?<provider>[^.]+)\.[^.]+\.?$", field=DomainName)
| provider := lower(provider)
// The rule's 15-minute window, rebuilt as a bucket so 30 days can be measured in one search.
| win := math:floor(@timestamp / 900000)
| groupBy([aid, ContextProcessId, win], function=[count(provider, distinct=true, as=providers), collect([ContextBaseFileName])], limit=max)
// Baseline: the distribution across windows. For top talkers instead, replace the last line with:
//   default(field=ContextBaseFileName, value="unknown")
//   | groupBy([aid, ContextBaseFileName], function=[max(providers, as=peak_providers), count(as=windows)], limit=max)
//   | sort(peak_providers, order=desc, limit=50)
| [count(), percentile(field=providers, percentiles=[50, 95, 99]), max(providers)]
```
The top-talkers view shows which programs on which hosts reach the most providers. Make the legitimate ones (an internal tool that calls OpenAI, Stripe and SendGrid together) host + process exclusions, then set the threshold just above the highest peak left, and check it against the p99. The rare tier matters most: if the baseline shows windows with a rare provider and two others, three-with-a-rare is too low for you.

## Suppression
Suppress by `host.id` (`aid`) for 24h. Alerts missing a key field are not suppressed. A scan tests keys for several minutes, and the next runs see the same process; they fold into one alert.

## Known false positives / exclusions
- A platform engineer running Terraform or another multi-provider tool. Terraform rarely touches the rare-tier providers, so it needs four common ones in one window.
- A developer's app that calls several of these APIs at start-up (OpenAI, Stripe and SendGrid together). Once known, exclude the host and the app.
- CI runners and AppSec hosts that run secret scanning with verification on. Exclude the host and the scanner. If their DNS events carry no process name, the pair can't match; exclude those hosts on their own for this rule, and say why in the comment.

## Blind spots
- **Testing switched off.** TruffleHog with `--no-verification`, or a stealer that sends what it found home without testing it, makes no calls. CS18 catches TruffleHog by name; the exfiltration shows in B06, B10 and N07.
- **The tester split across processes.** The worm's `node` often tests what TruffleHog found. If TruffleHog tests two providers and `node` another two, neither process reaches the threshold. Pairing them on the host is possible, but this rule stays per process to stay simple.
- **A scanner renamed to an editor or browser** (`code.exe`, `chrome`) is dropped by the exclusion. The exclusion matches names because DNS events carry no path.
- **An explicit proxy.** Endpoints set to use a proxy (a PAC file or proxy setting rather than a tunnelling client) look up the proxy's name, not `api.github.com`, and the endpoint rule goes dark. The Zscaler query still sees the calls.
- **Providers not on the list.** TruffleHog checks hundreds; the list holds the ones on developer machines that matter most. Add a provider by its key-checking endpoint, and to the rare tier if it seldom appears on your developer machines.
- Linux, where the lookup may not be charged to the program that asked (see Telemetry assumptions). The Zscaler query doesn't depend on it.
- **Zscaler: TLS not inspected.** Without inspection there's no user agent, so `trufflehog_user_agent` can't fire and browser calls can't be told apart; only the provider burst remains. A TruffleHog build with its user agent changed is also missed by that finding.

## Triage
- Name the program and its command line with the pivot query. TruffleHog or an unknown binary started by `node` under `npm` or `bun`, from a temp or cache folder, is the worm. Find the npm package installed just before `first_seen`. Then look for a new public GitHub repository under the developer's account and a new workflow file in their repositories.
- Rotate everything on that host the scan could reach, starting with the providers in `tested` (`provider` in LogScale): those keys were found and tested. Then rotate npm, GitHub and cloud tokens, `.env` secrets and SSH keys.

Pivot query, from a day before `first_seen` (the process may have started earlier) to the alert:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE host.id == "<host.id>"
  AND (data.TargetProcessId == "<data.ContextProcessId>" OR data.ContextProcessId == "<data.ContextProcessId>")
  AND event.action IN ("processrollup2", "syntheticprocessrollup2", "dnsrequest")
| KEEP @timestamp, event.action, user.name, process.executable, process.command_line, process.parent.name, data.DomainName
| SORT @timestamp ASC
```
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|DnsRequest)$/ aid="<aid>"
| TargetProcessId="<ContextProcessId>" or ContextProcessId="<ContextProcessId>"
| select([@timestamp, #event_simpleName, UserName, ImageFileName, CommandLine, ParentBaseFileName, DomainName])
```

## Test
On a lab host, put well-formed test keys for four providers (GitHub, AWS, OpenAI, SendGrid) in a file under a test folder.
- `trufflehog filesystem <folder>`: an alert. Run the pivot query on it and confirm it names TruffleHog: that proves the process ID links.
- The same with the binary renamed: the same alert. This is the case the rule exists for.
- A `node` script that calls `api.github.com`, `registry.npmjs.org` and `api.sendgrid.com`: an alert, with `node` as the process.
- `trufflehog filesystem <folder> --no-verification`: nothing here, by design. CS18 alerts by name.
- On a Linux lab box, run the first test and check which process the lookups are charged to.
- Zscaler: after the first test, run the Zscaler query over the test window. Expect `trufflehog_user_agent` where the traffic is inspected (that also confirms the user agent), and `keys_tested` where it isn't.
