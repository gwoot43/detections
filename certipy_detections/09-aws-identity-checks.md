---
id: AWS-01
name: AWS CLI identity check run repeatedly for a profile (aws sts get-caller-identity --profile)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1087.004, T1552.001, T1078.004]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.name, user.name, profile]
  duration: 24h
  missing_fields: do_not_suppress
---
`aws sts get-caller-identity` is AWS's `whoami`. One run is normal; the same check run again and again is someone testing keys. This counts the checks per host, user and `--profile` (`(default)` when none was named, which is also what keys passed in environment variables look like), and keeps the ones run 5 or more times in the window.

TruffleHog doesn't show up here: it checks AWS keys through the STS API from its own binary, not the CLI. CS17 covers that.

Run hourly over the last hour.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for AWS CLI identity checks
#event_simpleName=ProcessRollup2 FileName=/^aws(\.exe)?$/i CommandLine=/get-caller-identity/i
//Pull out the profile each check named
| regex("--profile[ =](?<profile>[^ ]+)", field=CommandLine, strict=false)
| default(field=profile, value="(default)")
| default(field=UserName, value="unknown")
//Count the checks per host, user and profile
| groupBy([ComputerName, UserName, profile], function=[count(as=runs), max(@timestamp, as=LastRun)], limit=max)
//Keep profiles checked 5+ times (starting value)
| runs >= 5
| LastRun := formatTime("%Y-%m-%d %H:%M:%S", field=LastRun, timezone="Australia/Sydney")
```
Leave out `| runs >= 5` to see every count.

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for AWS CLI identity checks
| WHERE event.action == "processrollup2" AND process.name IN ("aws.exe", "aws")
  AND process.command_line LIKE "*get-caller-identity*"
// Pull out the profile each check named
| GROK process.command_line """--profile[ =](?<profile>[^ ]+)"""
| EVAL profile = COALESCE(profile, "(default)")
// Count the checks per host, user and profile
| STATS runs = COUNT(*), last_run = MAX(@timestamp) BY host.name, user.name, profile
// Keep profiles checked 5+ times (starting value)
| WHERE runs >= 5
```
Suppress by host, user and profile for 24h.

## Before turning it on
Run it over a week without the last line to see the normal counts, and set the 5 from it. Scripts and CI jobs that check their identity in a loop go in as host + user pairs.

## What it misses
- Checks made outside the CLI: the AWS SDKs (TruffleHog, scripts, stealers), `Get-STSCallerIdentity` in PowerShell, AWS CLI v1 (runs as Python).
- Keys checked from the attacker's own machine: only CloudTrail sees that.
- Many profiles each checked once or twice: under the count per profile.

## When it fires
Find where that profile's credentials live on the host (`~/.aws/credentials`, `AWS_*` environment variables) and what ran just before, then check CloudTrail for the keys being used from elsewhere. Rotate any key that was live.
