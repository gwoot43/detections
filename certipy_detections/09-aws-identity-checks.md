---
id: AWS-01
name: AWS CLI identity checks repeated, or run by someone who never used the AWS CLI (testing found keys)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1087.004, T1552.001, T1078.004]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name, finding]
  duration: 24h
  missing_fields: do_not_suppress
---
`aws sts get-caller-identity` is AWS's `whoami`: engineers run it all the time, so on its own it's noise. Two shapes aren't:
- **Repeated checks:** 5 or more in an hour, or 3 or more different profiles. That's someone working through a batch of keys to see which are live.
- **A first-ever use:** the user has never run the AWS CLI on that host in 30 days, and the first thing they did was check an identity. That's what an attacker does with keys found on a machine that isn't a developer's.

People who use AWS every day stay quiet under both.

TruffleHog doesn't show up here: it checks AWS keys by calling the STS API directly from its own binary, not through the CLI. CS17 sees that, as a lookup of `sts.amazonaws.com` from a process that also tests other providers.

Run hourly over the last 30 days.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for AWS CLI runs
#event_simpleName=ProcessRollup2 FileName=/^aws(\.exe)?$/i aid=*
| default(field=UserName, value="unknown")
//Mark identity checks from the last hour, with the profile each named
| _now := now()
| age := _now - @timestamp
| case {
    CommandLine=/get-caller-identity/i age<3600000 | recent_check := 1 | regex("--profile[ =](?<profile>[^ ]+)", field=CommandLine, strict=false);
    * | recent_check := 0;
  }
//Group by host and user: their first AWS CLI run in the window, and recent identity checks
| groupBy([aid, UserName], function=[max(age, as=oldest_run_age), sum(recent_check, as=recent_checks), count(profile, distinct=true, as=profiles), collect([CommandLine, ParentBaseFileName], limit=5)], limit=max)
//Label and keep: 5+ checks or 3+ profiles in the hour, or checks by someone whose first AWS CLI run was this hour.
//Each branch is piped filters; deliberately no * branch, so anything else is dropped.
| case {
    recent_checks >= 5 | finding := "repeated_identity_checks";
    profiles >= 3 | finding := "repeated_identity_checks";
    recent_checks > 0 | oldest_run_age < 3600000 | finding := "first_aws_cli_use";
  }
//Add the host name and display results
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| table([ComputerName, UserName, finding, recent_checks, profiles, oldest_run_age, CommandLine, ParentBaseFileName])
```

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for AWS CLI runs
| WHERE event.action == "processrollup2" AND process.name IN ("aws.exe", "aws") AND host.id IS NOT NULL
// Pull out the profile named, if any
| GROK process.command_line """--profile[ =](?<profile>\S+)"""
// Group by host and user: their first AWS CLI run in the window, and identity checks in the last hour
| STATS first_aws = MIN(@timestamp),
        recent_checks = COUNT(*) WHERE process.command_line LIKE "*get-caller-identity*" AND @timestamp >= NOW() - 1 hour,
        profiles = COUNT_DISTINCT(profile) WHERE process.command_line LIKE "*get-caller-identity*"
          AND @timestamp >= NOW() - 1 hour,
        sample = TOP(process.command_line, 5, "asc") WHERE process.command_line LIKE "*get-caller-identity*",
        parents = VALUES(process.parent.name), host.name = VALUES(host.name)
    BY host.id, user.name
// Repeated checks, or a first-ever AWS CLI use that checked an identity (starting values)
| EVAL finding = CASE(recent_checks >= 5 OR profiles >= 3, "repeated_identity_checks",
                      recent_checks > 0 AND first_aws >= NOW() - 1 hour, "first_aws_cli_use", NULL)
| WHERE finding IS NOT NULL
```
Suppress by host, user and finding for 24h.

## Before turning it on
- Run it over 30 days without the last line and look at the spread of `recent_checks` and `profiles`; set the 5 and 3 from it. Scripts and CI jobs that check their identity in a loop go in as host + user pairs.
- The first run is noisy: everyone's first AWS CLI use in the 30 days looks new once.

## What it misses
- Identity checks made any way other than the CLI: the AWS SDKs (TruffleHog, scripts, stealers), AWS Tools for PowerShell (`Get-STSCallerIdentity`), or AWS CLI v1, which runs as Python. CS17 and its Zscaler checks cover the SDK route.
- Keys checked from the attacker's own machine. Only AWS's own logs (CloudTrail `GetCallerIdentity` from an address that isn't yours) see that.

## When it fires
Find which credentials were used: the profiles named, `AWS_*` environment variables, or a credentials file. Look at what ran just before (the parent, and how the keys got onto the host), then check CloudTrail for those keys being used from elsewhere. Rotate any key that was live.
