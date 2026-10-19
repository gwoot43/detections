---
id: CS17
name: Secret scanner on a host - a process tests keys against several unrelated services, or TruffleHog scans the file system (Shai-Hulud credential harvesting)
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1552.001, T1083]
data_source: CrowdStrike FDR DnsRequest and ProcessRollup2 (Windows, Linux, macOS)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The Shai-Hulud npm worm (2025, with variants through 2026) runs TruffleHog on every developer machine it infects to collect tokens and cloud keys. Infostealers do the same job their own way. Scanning a disk leaves nothing in FDR, which doesn't record file reads, but two things around it do. The rule looks for both on the same process, behaviour first:

1. **Activity (primary).** By default TruffleHog checks each secret it finds by calling that provider's API: AWS's identity service (STS) for an AWS key, GitHub's API for a GitHub token, npm's registry for an npm token. A stealer testing what it took does the same. So one process contacts three or more unrelated providers' key-checking endpoints within 15 minutes. Real tools talk to one provider: `gh` to GitHub, `aws` to AWS, `npm` to npm. This works whatever the program is called.
2. **Filename (fallback).** TruffleHog, recognised by name or by flags only it has (`--only-verified`, `--results`, `--no-verification`), scanning the file system rather than a git repository. Teams scan repositories in CI and pre-commit hooks. This catches a scan with checking switched off, or one that found too few keys to make a burst.

When both fire on the same process, the alert carries the command line next to the providers it tested.

- **Exclusion by newness:** it's the host's first detection in the 7-day lookback. Platform engineers' multi-provider tools (Terraform), CI runners and a security team's scheduled scans have a history. There is no fleet-wide rarity test, because a worm runs on many machines at once.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Two kinds of event, joined below on the process: lookups in the providers' domains (cheap, indexed),
// and process starts of TruffleHog by name or by its own flags.
| WHERE (event.action == "DnsRequest"
         AND dns.question.registered_domain IN ("amazonaws.com", "github.com", "npmjs.org", "openai.com", "anthropic.com", "stripe.com",
                                                "sendgrid.com", "twilio.com", "mailgun.net", "datadoghq.com", "heroku.com", "digitalocean.com",
                                                "cloudflare.com"))
     OR (event.action IN ("ProcessRollup2", "SyntheticProcessRollup2")
         AND (process.name IN ("trufflehog", "trufflehog.exe") OR process.command_line LIKE "*--only-verified*"
              OR process.command_line LIKE "*--results*" OR process.command_line LIKE "*--no-verification*"))
| EVAL dns.question.name = TO_LOWER(dns.question.name),
       // Activity: the endpoint a program calls to test a key, one per provider. AWS keys are tested against STS.
       verify = event.action == "DnsRequest"
                AND (dns.question.name RLIKE "sts(\\.[a-z0-9-]+)?\\.amazonaws\\.com"
                     OR dns.question.name IN ("api.github.com", "registry.npmjs.org", "api.openai.com", "api.anthropic.com", "api.stripe.com",
                                              "api.sendgrid.com", "api.twilio.com", "api.mailgun.net", "api.datadoghq.com", "api.heroku.com",
                                              "api.digitalocean.com", "api.cloudflare.com")),
       // Filename fallback: TruffleHog scanning the file system, not a git repository.
       named = event.action != "DnsRequest" AND TO_LOWER(process.command_line) RLIKE ".* filesystem( .*)?"
| WHERE verify OR named
// One row per process: the providers it tested and when, and whether it started as a TruffleHog file-system scan.
| STATS providers = COUNT_DISTINCT(CASE(verify, dns.question.registered_domain, NULL)),
        verify_first = MIN(CASE(verify, @timestamp, NULL)), verify_last = MAX(CASE(verify, @timestamp, NULL)),
        by_name = MAX(CASE(named, 1, 0)), first_seen = MIN(@timestamp),
        dns.question.name = VALUES(CASE(verify, dns.question.name, NULL)), process.command_line = VALUES(process.command_line),
        process.executable = VALUES(process.executable), process.parent.name = VALUES(process.parent.name),
        user.name = VALUES(user.name), host.name = VALUES(host.name)
    BY host.id, process.entity_id
// Activity first: three or more providers within 15 minutes. Then the filename fallback.
| EVAL burst = providers >= 3 AND DATE_DIFF("minute", verify_first, verify_last) <= 15
| WHERE burst OR by_name == 1
| EVAL finding = CASE(burst AND by_name == 1, "TruffleHog scan that tested keys",
                      burst, "keys tested against several providers",
                      "TruffleHog file-system scan (by name)")
// Newness: the host's first detection in the 7 days. Terraform users, CI runners and scheduled scans have a history.
| INLINE STATS host_first = MIN(first_seen) BY host.id
| WHERE host_first >= NOW() - 2 hours
| KEEP host.id, host.name, finding, providers, dns.question.name, process.command_line, process.executable, process.parent.name,
       user.name, process.entity_id, first_seen
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=/^(DnsRequest|ProcessRollup2|SyntheticProcessRollup2)$/
// Two kinds of event, joined below on the process (DNS: ContextProcessId; process start: TargetProcessId).
| case {
    // Activity: the endpoint a program calls to test a key, one per provider. The provider is the name's last two labels.
    #event_simpleName=DnsRequest
      | DomainName := lower(DomainName)
      | DomainName=/^(sts(\.[a-z0-9-]+)?\.amazonaws\.com|api\.github\.com|registry\.npmjs\.org|api\.(openai|anthropic|stripe|sendgrid|twilio|heroku|digitalocean|cloudflare)\.com|api\.mailgun\.net|api\.datadoghq\.com)\.?$/
      | regex("(?<provider>[^.]+\.[^.]+)\.?$", field=DomainName)
      | falconPID := ContextProcessId | verify_ts := @timestamp;
    // Filename fallback: TruffleHog, by name or by its own flags, scanning the file system rather than a git repository.
    #event_simpleName=/ProcessRollup2$/ CommandLine=/ filesystem( |$)/i
      (FileName=/^trufflehog(\.exe)?$/i or CommandLine=/--only-verified|--results[ =]|--no-verification/i)
      | falconPID := TargetProcessId | named := 1;
  }
// One row per process: the providers it tested and when, and whether it started as a TruffleHog file-system scan.
| groupBy([aid, falconPID], function=[count(provider, distinct=true, as=providers), min(verify_ts, as=verify_first),
                                      max(verify_ts, as=verify_last), count(named, as=by_name), min(@timestamp, as=first_seen),
                                      collect([ComputerName, DomainName, ImageFileName, CommandLine, ParentBaseFileName])], limit=max)
| default(field=[verify_first, verify_last], value=0)
// Activity first: three or more providers within 15 minutes. Then the filename fallback.
| test((providers >= 3 AND verify_last - verify_first <= 900000) OR by_name > 0)
| case {
    test(providers >= 3 AND by_name > 0) | finding := "TruffleHog scan that tested keys";
    test(providers >= 3) | finding := "keys tested against several providers";
    * | finding := "TruffleHog file-system scan (by name)";
  }
// Newness: the host's first detection in the 7 days.
| groupBy([aid], function=[min(first_seen, as=host_first), collect([ComputerName, finding, falconPID, DomainName, CommandLine, ParentBaseFileName])])
| _now := now()
| test(host_first > _now - 7200000)
```

When the activity fires on a renamed copy or a stealer, the process-start half isn't in the query (it only fetches TruffleHog's). The triage step below names the program from `process.entity_id` / `falconPID`.

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and a host alerts once, at its first detection.

## Known false positives / exclusions
- A platform engineer running Terraform or a similar multi-provider tool for the first time this week. It alerts once, then has a history if they run it at least weekly.
- A developer's app that calls several of these APIs at start-up (OpenAI, Stripe and SendGrid together), or a developer scanning a folder with TruffleHog, for the first time this week. The program and command line make it quick to close.

## Blind spot
- A renamed scanner run with checking switched off and none of TruffleHog's flags makes no network calls and isn't recognised by name.
- A stealer that sends what it found home without testing it doesn't show here; the exfiltration does (B06, B10, N07).

## Triage
- Read `finding`. "Keys tested against several providers" without a name: identify the program. In LogScale: `#event_simpleName=/ProcessRollup2$/ aid=<host.id> TargetProcessId=<process.entity_id>` gives the path, command line and parent.
- TruffleHog or an unknown binary started by `node` under `npm` or `bun`, from a temp or cache folder, is the worm. Find the npm package installed just before `first_seen`. Then look for a new public GitHub repository under the developer's account and a new workflow file in their repositories.
- Rotate everything on that host the scan could reach, starting with the providers in `dns.question.name`: those keys were found and tested. Then rotate npm, GitHub and cloud tokens, `.env` secrets and SSH keys.

## Test
On a lab host, put three well-formed test keys (GitHub, AWS and OpenAI formats) in a file under a test folder.
- Run `trufflehog filesystem <folder>`. It should alert within the hour as "TruffleHog scan that tested keys".
- Rename the binary and run it again on a second host: "keys tested against several providers".
- Run `trufflehog filesystem <folder> --no-verification` on a third: "TruffleHog file-system scan (by name)".
