---
id: CS17
name: One process tests credentials against several unrelated online services within minutes (secret scanner such as TruffleHog, or a stealer)
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1552.001, T1083]
data_source: CrowdStrike FDR DnsRequest (ProcessRollup2 for the by-name query)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The Shai-Hulud npm worm (2025, with variants through 2026) runs TruffleHog on every developer machine it infects to collect tokens and cloud keys. Infostealers do the same job their own way. Scanning a disk leaves nothing in FDR, which doesn't record file reads, but what comes next does. By default TruffleHog verifies each secret it finds by calling that provider's API: AWS's identity service for an AWS key, GitHub's API for a GitHub token, npm's registry for an npm token. A stealer testing what it took does the same. So one short-lived process contacts several unrelated providers' credential endpoints within minutes. Real tools talk to one provider: `gh` to GitHub, `aws` to AWS, `npm` to npm.

- **Anchor:** DNS lookups of the API endpoints a program calls to check a key, one per provider: AWS STS, GitHub, npm, OpenAI, Anthropic, Stripe, SendGrid, Twilio, Mailgun, Datadog, Heroku, DigitalOcean and Cloudflare. People reach these providers through their websites, so browsers rarely look the API endpoints up.
- **Corroborating property:** one process reaches three or more different providers, all within 15 minutes.
- **Exclusion by newness:** it's the host's first such burst in the 7-day lookback. Platform engineers' tools that legitimately touch several providers at once (Terraform) and CI runners have a history. There is no fleet-wide rarity test, because a worm runs on many machines at once.

It doesn't depend on the tool's name, so it catches a renamed TruffleHog, other scanners that verify (`gitleaks` doesn't, `noseyparker` can), and stealers. A query matching TruffleHog by name is below, as a quick second check.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Anchor: lookups in the providers' domains (cheap, indexed), narrowed below to the endpoints that check a key.
| WHERE event.action == "DnsRequest"
  AND dns.question.registered_domain IN ("amazonaws.com", "github.com", "npmjs.org", "openai.com", "anthropic.com", "stripe.com", "sendgrid.com",
                                         "twilio.com", "mailgun.net", "datadoghq.com", "heroku.com", "digitalocean.com", "cloudflare.com")
| EVAL dns.question.name = TO_LOWER(dns.question.name)
// The endpoint a program calls to test a key, one per provider. AWS keys are tested against STS (global or regional).
| WHERE dns.question.name RLIKE "sts(\\.[a-z0-9-]+)?\\.amazonaws\\.com"
   OR dns.question.name IN ("api.github.com", "registry.npmjs.org", "api.openai.com", "api.anthropic.com", "api.stripe.com", "api.sendgrid.com",
                            "api.twilio.com", "api.mailgun.net", "api.datadoghq.com", "api.heroku.com", "api.digitalocean.com", "api.cloudflare.com")
// One row per process: how many different providers it reached, and over how long.
| STATS providers = COUNT_DISTINCT(dns.question.registered_domain), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        dns.question.name = VALUES(dns.question.name), process.name = VALUES(process.name), host.name = VALUES(host.name)
    BY host.id, process.entity_id
// Behaviour: three or more providers within 15 minutes. A real tool talks to one; a scanner or stealer testing keys talks to many at once.
| WHERE providers >= 3 AND DATE_DIFF("minute", first_seen, last_seen) <= 15
// Newness: the host's first such burst in the 7 days. Terraform users and CI runners have a history.
| INLINE STATS host_first = MIN(first_seen) BY host.id
| WHERE host_first >= NOW() - 2 hours
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=DnsRequest
| DomainName := lower(DomainName)
// Anchor: the endpoint a program calls to test a key, one per provider. AWS keys are tested against STS (global or regional).
| DomainName=/^(sts(\.[a-z0-9-]+)?\.amazonaws\.com|api\.github\.com|registry\.npmjs\.org|api\.(openai|anthropic|stripe|sendgrid|twilio|heroku|digitalocean|cloudflare)\.com|api\.mailgun\.net|api\.datadoghq\.com)\.?$/
// The provider is the name's last two labels (amazonaws.com, github.com …).
| regex("(?<provider>[^.]+\.[^.]+)\.?$", field=DomainName)
// One row per process: how many different providers it reached, and over how long.
| groupBy([aid, ContextProcessId], function=[count(provider, distinct=true, as=providers), min(@timestamp, as=first_seen),
                                             max(@timestamp, as=last_seen), collect([ComputerName, DomainName])], limit=max)
// Behaviour: three or more providers within 15 minutes.
| test(providers >= 3 AND last_seen - first_seen <= 900000)
// Newness: the host's first such burst in the 7 days.
| groupBy([aid], function=[min(first_seen, as=host_first), collect([ComputerName, ContextProcessId, DomainName])])
| _now := now()
| test(host_first > _now - 7200000)
```
DNS events don't carry the process name. The triage step below names the program from `process.entity_id` / `ContextProcessId`.

**Same tool by name** (quick and exact, but only while it's called `trufflehog` or passes its own flags). It looks for TruffleHog scanning the file system rather than a git repository, which is what teams do in CI and pre-commit hooks:
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action IN ("ProcessRollup2", "SyntheticProcessRollup2")
  AND (process.name IN ("trufflehog", "trufflehog.exe")
       OR process.command_line LIKE "*--only-verified*" OR process.command_line LIKE "*--results*" OR process.command_line LIKE "*--no-verification*")
  AND TO_LOWER(process.command_line) RLIKE ".* filesystem( .*)?"
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, process.executable, process.command_line, process.entity_id,
       _id, _version, _index
```
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ CommandLine=/ filesystem( |$)/i
| case {
    FileName=/^trufflehog(\.exe)?$/i;
    CommandLine=/--only-verified|--results[ =]|--no-verification/i;
  }
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId])
```

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and a host alerts once, at its first burst.

## Known false positives / exclusions
- A platform engineer running Terraform or a similar multi-provider tool for the first time this week. It alerts once, then has a history if they run it at least weekly.
- A developer's app that calls several of these APIs at start-up (OpenAI, Stripe and SendGrid together), run for the first time this week. The process name from triage makes it quick to close.

## Blind spot
- A scan run with verification switched off (`--no-verification`) makes no calls; the by-name query covers TruffleHog itself.
- A stealer that sends what it found home without testing it doesn't show here; the exfiltration does (B06, B10, N07).

## Triage
- Name the program. In LogScale: `#event_simpleName=/ProcessRollup2$/ aid=<host.id> TargetProcessId=<process.entity_id>` gives the path, command line and parent. TruffleHog (or a renamed copy) started by `node` under `npm` or `bun`, from a temp or cache folder, is the worm.
- For the worm: find the npm package installed just before `first_seen`. Then look for a new public GitHub repository under the developer's account and a new workflow file in their repositories.
- Rotate everything on that host the scan could reach, starting with the providers in `dns.question.name`: those keys were found and tested. Then rotate npm, GitHub and cloud tokens, `.env` secrets and SSH keys.

## Test
On a lab host, put three well-formed test keys (GitHub, AWS and OpenAI formats) in a file under a test folder. Run `trufflehog filesystem <folder>`. Its verification calls should alert within the hour; the by-name query should match too.
