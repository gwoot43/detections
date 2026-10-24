---
id: AWS-01
name: AWS CLI identity checks across several profiles by one user on one host (aws sts get-caller-identity --profile enumeration)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1087.004, T1552.001, T1078.004]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.name, user.name]
  duration: 24h
  missing_fields: do_not_suppress
---
`aws sts get-caller-identity` is AWS's `whoami`. Engineers check one or two profiles; someone enumerating the credentials on a host checks one profile after another to see which keys are live. This groups the checks by user and host, lists the profiles each one checked (`(default)` when none was named, which is also what keys passed in environment variables look like), and keeps users who checked 3 or more different profiles within the same 2-hour window. The window is the gate: a burst of checks is enumeration, the same profiles spread over a week are someone doing their job, and it also lets the query run over any time range as a hunt without counts piling up.

TruffleHog doesn't show up here: it checks AWS keys through the STS API from its own binary, not the CLI. CS17 covers that.

Run hourly over the last 2 hours.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for AWS CLI identity checks
#event_simpleName=ProcessRollup2 FileName=/^aws(\.exe)?$/i CommandLine=/get-caller-identity/i
//Pull out the profile each check named
| regex("--profile[ =](?<profile>[^ ]+)", field=CommandLine, strict=false)
| default(field=profile, value="(default)")
| default(field=UserName, value="unknown")
//The 2-hour window each check falls in
| window := math:floor(@timestamp / 7200000)
//Group by window, user and host: how many different profiles they checked, and which
| groupBy([window, UserName, ComputerName], function=[count(profile, distinct=true, as=profiles), count(as=runs), collect([profile]), min(@timestamp, as=FirstRun), max(@timestamp, as=LastRun)], limit=max)
//Keep users who checked 3+ different profiles in one window (starting value)
| profiles >= 3
//First and last check in the window, in Sydney time
| FirstRun := formatTime("%Y-%m-%d %H:%M:%S", field=FirstRun, timezone="Australia/Sydney")
| LastRun := formatTime("%Y-%m-%d %H:%M:%S", field=LastRun, timezone="Australia/Sydney")
| table([ComputerName, UserName, profiles, runs, profile, FirstRun, LastRun])
```
Leave out `| profiles >= 3` to see every user and host.

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for AWS CLI identity checks
| WHERE event.action == "processrollup2" AND process.name IN ("aws.exe", "aws")
  AND process.command_line LIKE "*get-caller-identity*"
// Pull out the profile each check named
| GROK process.command_line """--profile[ =](?<profile>[^ ]+)"""
| EVAL profile = COALESCE(profile, "(default)")
// Group by 2-hour window, user and host: how many different profiles they checked, and which
| STATS profiles = COUNT_DISTINCT(profile), runs = COUNT(*), profile_list = VALUES(profile),
        first_run = MIN(@timestamp), last_run = MAX(@timestamp)
    BY window = BUCKET(@timestamp, 2 hours), user.name, host.name
// Keep users who checked 3+ different profiles in one window (starting value)
| WHERE profiles >= 3
```
Suppress by host and user for 24h.

## Before turning it on
Run it over a week without the last line to see how many profiles people normally check in 2 hours, and set the 3 from it. Scripts and CI jobs that check their identity in a loop go in as host + user pairs.

## What it misses
- Checks made outside the CLI: the AWS SDKs (TruffleHog, scripts, stealers), `Get-STSCallerIdentity` in PowerShell, AWS CLI v1 (runs as Python).
- Keys checked from the attacker's own machine: only CloudTrail sees that.
- A burst that straddles a window edge is split in two, and each half may stay under 3. The hourly run over 2 hours sees each window twice, which narrows that gap; suppression folds the repeat.
- One profile checked over and over (keys swapped in through environment variables all show as `(default)`): `runs` shows it, but only the profile count alerts. If you see that, add `OR runs >= 10` to the last line in ES|QL; in LogScale, swap `| profiles >= 3` for `| case { profiles >= 3; runs >= 10; }` (each branch is an OR).

## When it fires
`profile` lists what was checked. Find where those credentials live on the host (`~/.aws/credentials`, `AWS_*` environment variables) and what ran just before, then check CloudTrail for the keys being used from elsewhere. Rotate any key that was live.
