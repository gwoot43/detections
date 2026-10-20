---
id: CS17
name: Secret scanner on a host - keys tested against several unrelated services (activity), or TruffleHog run (filename fallback); Shai-Hulud credential harvesting
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1552.001, T1083]
data_source: CrowdStrike FDR DnsRequest and ProcessRollup2 (Zscaler as an alternative for the activity half)
suppression:
  fields: [host.id, finding]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The Shai-Hulud npm worm (2025, with variants through 2026) runs TruffleHog on every developer machine it infects, then uses what it finds. Infostealers do the same job their own way. Scanning a disk leaves nothing in FDR, which doesn't record file reads, but two things around it do:

1. **Activity (primary).** Found keys get tested against their providers' APIs: AWS's identity service (STS), GitHub's API, npm's registry. TruffleHog does it by default, and so does the worm's own `node` process, which runs `npm whoami` and calls GitHub with what TruffleHog found. Stealers do it too. So some process contacts several unrelated providers' key-checking endpoints within 15 minutes. Real tools talk to one provider: `gh` to GitHub, `aws` to AWS. This works whatever the program is called.
2. **Filename (fallback).** TruffleHog starting, recognised by name, its Docker image (`trufflesecurity/trufflehog`) or flags only it has (`--only-verified`, `--no-verification`, `--results=verified…`), with any scan source. This catches a scan with checking switched off, or one that found too little to make a burst.

The tester is often not the scanner (the worm's `node` tests what TruffleHog found), so the two halves are paired on the **host, per hour**, not on the process.

- **Burst, not lifetime:** providers are counted per process in fixed 15-minute windows. A long scan, or a long-running process, is judged on its busiest window, not its whole life.
- **Provider tiers:** GitHub, npm, AWS STS and the AI APIs are what code editors (Copilot, AI assistants, AWS Toolkit), the npm CLI and LLM proxies call all day. Mail, SMS and hosting APIs (SendGrid, Twilio, Mailgun, Heroku, DigitalOcean) rarely show up on a developer's machine. A burst is four or more providers, or three with at least one rare one. Code editors are dropped by name where the process start is in the search.
- **Exclusions:** CI runners and AppSec hosts, which scan by design (placeholders), and newness. A finding alerts the first time it *reaches Elastic* for that host in the 7-day lookback. It's keyed on host *and* finding, so a developer's own TruffleHog run days ago doesn't blind the host to a key-testing burst today. It uses arrival time, so a late event still alerts. There is no fleet-wide rarity test, because a worm runs on many machines at once.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Three kinds of event, joined below on the process (host.id + process.entity_id):
// - lookups of the endpoints a program calls to test a key (filtered on the indexed registered domain first);
// - TruffleHog starting, by name, Docker image or its own flags (the filename fallback);
// - for context, starts in the last day of the programs that usually do the testing (script runtimes, anything in a
//   temp or cache folder) and of code editors, which test keys for their extensions and are dropped below.
| WHERE (event.action == "dnsrequest"
         AND dns.question.registered_domain IN ("amazonaws.com", "github.com", "npmjs.org", "openai.com", "anthropic.com", "stripe.com",
                                                "datadoghq.com", "datadoghq.eu", "cloudflare.com", "sendgrid.com", "twilio.com",
                                                "mailgun.net", "heroku.com", "digitalocean.com"))
     OR (event.action IN ("processrollup2", "syntheticprocessrollup2")
         AND (process.name IN ("trufflehog", "trufflehog.exe") OR process.command_line LIKE "*trufflesecurity/trufflehog*"
              OR process.command_line LIKE "*--only-verified*" OR process.command_line LIKE "*--no-verification*"
              OR process.command_line LIKE "*--results*"
              OR (@timestamp >= NOW() - 1 day
                  AND (process.name IN ("node", "node.exe", "bun", "bun.exe", "deno", "deno.exe", "python", "python3", "python.exe",
                                        "Code.exe", "code", "Cursor.exe", "cursor", "Windsurf.exe", "windsurf")
                       OR process.name LIKE "Code Helper*" OR process.name LIKE "Cursor Helper*"
                       OR process.executable LIKE "/tmp/*" OR process.executable LIKE "*/.cache/*"
                       OR process.executable LIKE """*\\AppData\\Local\\Temp\\*"""))))
| EVAL d = TO_LOWER(dns.question.name), cmd = TO_LOWER(COALESCE(process.command_line, "")),
       // The provider whose key-checking endpoint was looked up. AWS keys are tested against STS (global, regional or FIPS).
       provider = CASE(d RLIKE "sts(-fips)?(\\.[a-z0-9-]+)?\\.amazonaws\\.com", "aws", d == "api.github.com", "github",
                       d == "registry.npmjs.org", "npm", d == "api.openai.com", "openai", d == "api.anthropic.com", "anthropic",
                       d == "api.stripe.com", "stripe", d IN ("api.datadoghq.com", "api.datadoghq.eu"), "datadog",
                       d == "api.cloudflare.com", "cloudflare", d == "api.sendgrid.com", "sendgrid", d == "api.twilio.com", "twilio",
                       d == "api.mailgun.net", "mailgun", d == "api.heroku.com", "heroku", d == "api.digitalocean.com", "digitalocean",
                       NULL),
       // Mail, SMS and hosting APIs rarely show up on a developer's machine; GitHub, npm, AWS and the AI APIs do.
       rare = provider IN ("sendgrid", "twilio", "mailgun", "heroku", "digitalocean"),
       // Filename fallback: TruffleHog by name, Docker image or its own flags, any scan source; CI and AppSec hosts excluded.
       named = event.action != "dnsrequest" AND NOT host.id IN ("<ci_runner_aid>", "<appsec_aid>")
               AND (process.name IN ("trufflehog", "trufflehog.exe") OR cmd LIKE "*trufflesecurity/trufflehog*"
                    OR cmd RLIKE ".*--(only-verified|no-verification|results[ =](verified|unknown|unverified|filtered)).*"),
       editor = process.name IN ("Code.exe", "code", "Cursor.exe", "cursor", "Windsurf.exe", "windsurf")
                OR process.name LIKE "Code Helper*" OR process.name LIKE "Cursor Helper*",
       win = DATE_TRUNC(15 minutes, @timestamp)
| WHERE provider IS NOT NULL OR event.action != "dnsrequest"
// One row per process and 15-minute window: the providers it tested in that window.
| STATS providers = COUNT_DISTINCT(provider), rare_providers = COUNT_DISTINCT(CASE(rare, provider, NULL)), tested = VALUES(provider),
        named = MAX(CASE(named, 1, 0)), editor = MAX(CASE(editor, 1, 0)), first_seen = MIN(@timestamp), ingested = MIN(event.ingested),
        process.executable = VALUES(process.executable), process.command_line = VALUES(process.command_line),
        process.parent.name = VALUES(process.parent.name), user.name = VALUES(user.name), host.name = VALUES(host.name)
    BY host.id, process.entity_id, win
// A burst: four or more providers, or three with at least one rare one.
| EVAL burst = CASE(providers >= 4 OR (providers >= 3 AND rare_providers >= 1), 1, 0), hit = burst == 1 OR named == 1
// One row per process: its bursts and TruffleHog start, with context from its start event when that's in the search.
| STATS burst = MAX(burst), named = MAX(named), editor = MAX(editor), tested = VALUES(tested),
        first_seen = MIN(CASE(hit, first_seen, NULL)), ingested = MIN(CASE(hit, ingested, NULL)),
        process.executable = VALUES(process.executable), process.command_line = VALUES(process.command_line),
        process.parent.name = VALUES(process.parent.name), user.name = VALUES(user.name), host.name = VALUES(host.name)
    BY host.id, process.entity_id
// Keep processes with a burst or a TruffleHog start; drop code editors. A process with no start event in the search stays.
| WHERE (burst == 1 OR named == 1) AND editor == 0
// Host level, per hour: the worm's node often tests the keys TruffleHog found, so pair the halves on the host.
| EVAL hour = DATE_TRUNC(1 hour, first_seen)
| STATS any_burst = MAX(burst), any_named = MAX(named), tested = VALUES(tested), process.entity_id = VALUES(process.entity_id),
        process.executable = VALUES(process.executable), process.command_line = VALUES(process.command_line),
        process.parent.name = VALUES(process.parent.name), user.name = VALUES(user.name), host.name = VALUES(host.name),
        first_seen = MIN(first_seen), ingested = MIN(ingested)
    BY host.id, hour
| EVAL finding = CASE(any_burst == 1 AND any_named == 1, "TruffleHog run and keys tested on the same host",
                      any_burst == 1, "keys tested against several providers",
                      "TruffleHog run (by name)")
// Newness per host and finding, by arrival: the first time this finding reached Elastic for this host in the 7 days
// was in the last 2 hours. Late events still alert, and an older finding of one kind doesn't hide a new kind.
| INLINE STATS finding_first_ingested = MIN(ingested) BY host.id, finding
| WHERE finding_first_ingested >= NOW() - 2 hours
| KEEP host.id, host.name, finding, tested, process.entity_id, process.executable, process.command_line, process.parent.name,
       user.name, first_seen
```
A burst whose process started more than a day before the search (or isn't one of the usual testers) alerts with its `process.entity_id` but no path; the triage step names it. ES|QL can't fetch start events for just the flagged processes; the LogScale version below does.

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
// Bursts: per process and 15-minute window, the providers whose key-checking endpoint it looked up.
defineTable(name="bursts", include=[aid, falconPID, providers, provider, burst_ingested], query={
    #event_simpleName=DnsRequest
    // DNS is the busiest event: filter on the raw name first, then lower-case only what's left.
    | DomainName=/^(sts(-fips)?(\.[a-z0-9-]+)?\.amazonaws\.com|api\.github\.com|registry\.npmjs\.org|api\.(openai|anthropic|stripe|cloudflare|sendgrid|twilio|heroku|digitalocean)\.com|api\.mailgun\.net|api\.datadoghq\.(com|eu))\.?$/i
    | DomainName := lower(DomainName)
    | regex("(?<provider>[^.]+\.[^.]+)\.?$", field=DomainName)
    // Mail, SMS and hosting APIs rarely show up on a developer's machine; GitHub, npm, AWS and the AI APIs do.
    | regex("^(?<rare>sendgrid\.com|twilio\.com|mailgun\.net|heroku\.com|digitalocean\.com)$", field=provider, strict=false)
    | falconPID := ContextProcessId
    | win := math:floor(@timestamp / 900000)
    | groupBy([aid, falconPID, win], function=[count(provider, distinct=true, as=providers), count(rare, distinct=true, as=rare_providers),
                                             collect([provider]), min(@ingesttimestamp, as=burst_ingested)], limit=max)
    // A burst: four or more providers, or three with at least one rare one.
    | test(providers >= 4 OR (providers >= 3 AND rare_providers >= 1))
})
// Every event of a process with a burst (its start gives the context; its lookups keep it in the results when the
// start is older than the search), and TruffleHog starting by name, Docker image or its own flags (the fallback).
| #event_simpleName=/^(DnsRequest|ProcessRollup2|SyntheticProcessRollup2)$/
| case {
    #event_simpleName=DnsRequest | falconPID := ContextProcessId;
    * | falconPID := TargetProcessId;
  }
| match(table="bursts", field=[aid, falconPID], strict=false)
| case {
    #event_simpleName=/ProcessRollup2$/
      (FileName=/^trufflehog(\.exe)?$/i or CommandLine=/trufflesecurity\/trufflehog|--(only-verified|no-verification|results[ =](verified|unknown|unverified|filtered))/i)
      | named := 1;
    *;
  }
| providers=* or named=*
// CI runners and AppSec hosts scan by design (placeholders: Falcon agent IDs).
| !in(field="aid", values=["<ci_runner_aid>", "<appsec_aid>"])
// One row per process: its bursts and whether it started as TruffleHog, with context when its start is in the search.
| groupBy([aid, falconPID], function=[max(providers, as=providers), count(named, as=named), min(@timestamp, as=first_seen),
                                      min(burst_ingested, as=burst_ingested), min(@ingesttimestamp, as=first_ingested),
                                      collect([ComputerName, provider, ImageFileName, CommandLine, ParentBaseFileName])], limit=max)
// Code editors test keys for their extensions (Copilot, AI assistants, AWS Toolkit): drop them when the start names them.
| NOT ImageFileName=/[\\\/](code|cursor|windsurf)( helper[^\\\/]*)?(\.exe)?$/i
| default(field=[providers], value=0)
| ingest := coalesce([burst_ingested, first_ingested])
// Host level, per hour: the worm's node often tests the keys TruffleHog found, so pair the halves on the host.
| hour := math:floor(first_seen / 3600000)
| groupBy([aid, hour], function=[max(providers, as=providers), sum(named, as=named), min(ingest, as=ingest),
                                 collect([ComputerName, falconPID, provider, ImageFileName, CommandLine, ParentBaseFileName])])
| case {
    test(providers > 0 AND named > 0) | finding := "TruffleHog run and keys tested on the same host";
    test(providers > 0) | finding := "keys tested against several providers";
    * | finding := "TruffleHog run (by name)";
  }
// Newness per host and finding, by arrival: the first time this finding reached LogScale for this host was in the last 2 hours.
| groupBy([aid, finding], function=[min(ingest, as=first_arrival),
                                    collect([ComputerName, falconPID, provider, ImageFileName, CommandLine, ParentBaseFileName])])
| _now := now()
| test(first_arrival > _now - 7200000)
```
If your tenant doesn't have `defineTable`, run the bursts query as the inner query of `join(..., field=[aid, falconPID], key=[aid, falconPID], include=[providers, provider, burst_ingested], mode=left)` instead of `match`; the bursts are few, so `join`'s row cap isn't a problem.

**If endpoints use an explicit proxy** (a PAC file or proxy setting rather than a tunnelling client), they look up the proxy's name, not `api.github.com`, and the activity half goes dark in DNS. The proxy sees the destination instead. The same burst in Zscaler, per user and 15-minute window, run hourly over 2 hours (the filename fallback stays on the endpoint):
```esql
FROM logs-zscaler_zia.web-*
| EVAL d = TO_LOWER(url.domain),
       provider = CASE(d RLIKE "sts(-fips)?(\\.[a-z0-9-]+)?\\.amazonaws\\.com", "aws", d == "api.github.com", "github",
                       d == "registry.npmjs.org", "npm", d == "api.openai.com", "openai", d == "api.anthropic.com", "anthropic",
                       d == "api.stripe.com", "stripe", d IN ("api.datadoghq.com", "api.datadoghq.eu"), "datadog",
                       d == "api.cloudflare.com", "cloudflare", d == "api.sendgrid.com", "sendgrid", d == "api.twilio.com", "twilio",
                       d == "api.mailgun.net", "mailgun", d == "api.heroku.com", "heroku", d == "api.digitalocean.com", "digitalocean",
                       NULL)
| WHERE provider IS NOT NULL AND user.name IS NOT NULL
// One row per user, client and 15-minute window. The user agent stands in for the program.
| STATS providers = COUNT_DISTINCT(provider), rare_providers = COUNT_DISTINCT(CASE(provider IN ("sendgrid", "twilio", "mailgun", "heroku", "digitalocean"), provider, NULL)),
        tested = VALUES(provider), first_seen = MIN(@timestamp)
    BY user.name, source.ip, user_agent.original, win = DATE_TRUNC(15 minutes, @timestamp)
| WHERE providers >= 4 OR (providers >= 3 AND rare_providers >= 1)
```

**Check before deploying:**
- **Linux and macOS.** Run TruffleHog on a lab box against a folder of test keys and confirm the lookups appear with its process ID. TruffleHog is written in Go, and Go's resolver on Linux can send DNS itself. macOS routes lookups through `mDNSResponder`, so the process ID on the DNS event may not be the program that asked. That's where TruffleHog realistically runs (developer machines, CI), so test it before trusting the activity half there; the filename fallback doesn't depend on it.
- **`defineTable` and `match`** syntax on your tenant (the `join` alternative is above).

## Suppression
Suppress by `host.id`, `finding` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and each finding alerts once per host, when it first arrives.

## Known false positives / exclusions
- A platform engineer running Terraform or another multi-provider tool for the first time this week. Terraform rarely touches the rare-tier providers, so it needs four common ones in one window.
- A developer's app that calls several of these APIs at start-up (OpenAI, Stripe and SendGrid together). The program and command line make it quick to close.
- A code editor whose start is older than a day, so it isn't recognised as an editor. It alerts once for the host, then has a history.

## Blind spot
- A renamed scanner run with checking switched off and none of TruffleHog's flags makes no network calls and isn't recognised. A renamed copy run with just `--json` is in that group: `--json` is too common to match on, and so is `--no-update` (Composer uses it).
- A stealer that sends what it found home without testing it doesn't show here; the exfiltration does (B06, B10, N07).

## Triage
- Read `finding`. For a burst without a path, name the program. In LogScale: `#event_simpleName=/ProcessRollup2$/ aid=<host.id> TargetProcessId=<process.entity_id>` gives the path, command line and parent.
- TruffleHog or an unknown binary started by `node` under `npm` or `bun`, from a temp or cache folder, is the worm. Find the npm package installed just before `first_seen`. Then look for a new public GitHub repository under the developer's account and a new workflow file in their repositories.
- Rotate everything on that host the scan could reach, starting with the providers in `tested`: those keys were found and tested. Then rotate npm, GitHub and cloud tokens, `.env` secrets and SSH keys.

## Test
On a lab host, put well-formed test keys for four providers (GitHub, AWS, OpenAI, SendGrid) in a file under a test folder.
- Run `trufflehog filesystem <folder>`: "TruffleHog run and keys tested on the same host".
- On a second host, rename the binary and run it: "keys tested against several providers".
- On a third, run `trufflehog filesystem <folder> --no-verification`: "TruffleHog run (by name)".
- Run `docker run trufflesecurity/trufflehog filesystem /x` on a fourth: also "TruffleHog run (by name)".
