---
id: CS17
name: TruffleHog scans a host's file system for secrets (credential harvesting, as the Shai-Hulud worm does)
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1552.001, T1083]
data_source: CrowdStrike FDR ProcessRollup2 (Windows, Linux, macOS)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
TruffleHog is an open-source secret scanner. Teams run it on their code repositories, in CI or as a pre-commit hook. The Shai-Hulud npm worm (2025, with variants through 2026) downloaded it onto every developer machine it infected. It ran TruffleHog over the file system to collect tokens and cloud keys, then published them to GitHub. What separates the two uses is what gets scanned. Teams scan repositories. An attacker scans the machine, because the keys are in `.npmrc`, `.env` files, cloud configs and shell history.

- **Anchor:** TruffleHog starting, by its name or, for a renamed copy, by flags only TruffleHog has (`--only-verified`, `--results`, `--no-verification`).
- **Corroborating property:** it's scanning the file system (`filesystem`), not a git repository.
- **Exclusion by newness:** this host hasn't had the same parent run a TruffleHog file-system scan in 7 days. A security team's scheduled scan has a history. There is no fleet-wide rarity test, because a worm runs it on many machines at once.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Anchor: TruffleHog by name, or a renamed copy by flags only TruffleHog has.
| WHERE event.action IN ("ProcessRollup2", "SyntheticProcessRollup2")
  AND (process.name IN ("trufflehog", "trufflehog.exe")
       OR process.command_line LIKE "*--only-verified*" OR process.command_line LIKE "*--results*" OR process.command_line LIKE "*--no-verification*")
| EVAL cmd = TO_LOWER(process.command_line)
// Corroborating property: scanning the file system rather than a git repository.
| WHERE cmd RLIKE ".* filesystem( .*)?"
| EVAL process.parent.name = TO_LOWER(COALESCE(process.parent.name, "unknown"))
// One row per host and parent: when this first happened in the 7 days.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), runs = COUNT(*), process.command_line = VALUES(process.command_line),
        process.executable = VALUES(process.executable), user.name = VALUES(user.name), process.entity_id = VALUES(process.entity_id),
        host.name = VALUES(host.name)
    BY host.id, process.parent.name
// New on this host in the last 2 hours. A scheduled scan by your security team has a history.
| WHERE first_seen >= NOW() - 2 hours
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
// Anchor: TruffleHog by name, or a renamed copy by flags only TruffleHog has.
| case {
    FileName=/^trufflehog(\.exe)?$/i;
    CommandLine=/--only-verified|--results[ =]|--no-verification/i;
  }
// Corroborating property: scanning the file system rather than a git repository.
| CommandLine=/ filesystem( |$)/i
| parent := lower(ParentBaseFileName)
| default(field=parent, value="unknown", replaceEmpty=true)
// One row per host and parent: when this first happened in the 7 days.
| groupBy([aid, parent], function=[min(@timestamp, as=first_seen), count(as=runs), collect([ComputerName, UserName, ImageFileName, CommandLine])],
          limit=max)
// New on this host in the last 2 hours.
| _now := now()
| test(first_seen > _now - 7200000)
```

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run.

## Known false positives / exclusions
- A developer or security engineer scanning a folder on their own machine (`trufflehog filesystem .`). It alerts once per host and parent; the path and the person make it quick to close.
- A security team's server scan. It alerts the first time, then has a history if it runs at least weekly.

## Blind spot
A renamed copy run without any of the three flags isn't recognised. The worm ran it under its own name, with verification flags, so its pattern is covered. Other secret scanners (`gitleaks`, `noseyparker`) aren't covered; their `dir`/`detect` and `scan` modes would need their own branch.

## Triage
- Look at the parent and where the binary is. `node` under `npm` or `bun`, or a TruffleHog binary just downloaded into a temp or cache folder, is the worm. A person's terminal and a known path is someone's own scan.
- For the worm: find the npm package installed just before `first_seen`, then look for a new public GitHub repository under the developer's account (Shai-Hulud names them after itself) and a new workflow file in their repositories.
- Rotate everything the scan could reach on that host: npm, GitHub and cloud tokens, `.env` secrets and SSH keys.

## Test
On a lab host, download TruffleHog and run it from a script rather than a terminal, for example `python -c "import subprocess; subprocess.run(['trufflehog', 'filesystem', '/home', '--only-verified'])"`. It should alert within the hour, with `python` as the parent.
