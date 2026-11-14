---
id: I16
name: Password spray against Active Directory followed by a success from the same source
category: identity
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1110.003, T1078.002]
data_source: Windows Security 4625, 4771, 4624 and 4768 on domain controllers and servers
suppression:
  fields: [source.ip]
  duration: 24h
  missing_fields: do_not_suppress
---

`I05` alerts on the spray itself: one source failing against many accounts. This rule is the part that matters
afterwards. **One of the sprayed guesses worked.** The same source that failed across ten or more accounts then gets a
successful network or RDP logon, or a Kerberos TGT, for a small number of accounts.

It counts Kerberos as well as NTLM. A Kerbrute-style spray produces `4771` (pre-authentication failed, status `0x18`)
rather than `4625`, and its success is a `4768` TGT rather than a `4624`. A rule that reads only `4625`/`4624` misses
the most common spray tool.

The Entra twin is `S13`/`S14`/`S15`, which already flag a correct guess even when MFA stopped the sign-in. The VPN
twin is `N02`.

## Query

Run every 15 minutes with a 1-hour lookback.

```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code IN ("4625", "4771", "4624", "4768")
  AND source.ip IS NOT NULL
| EVAL loopback = CIDR_MATCH(source.ip, "127.0.0.0/8", "::1/128"),   // local logons (IIS, Exchange) are not a spray source
       acct = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
       status = TO_LOWER(COALESCE(winlog.event_data.Status, "")),
       failed = event.code == "4625" OR (event.code == "4771" AND status == "0x18"),
       succeeded = (event.code == "4624" AND winlog.event_data.LogonType IN ("3", "10"))
                   OR (event.code == "4768" AND status == "0x0")
| WHERE NOT loopback AND acct != "" AND acct != "-" AND NOT ENDS_WITH(acct, "$") AND (failed OR succeeded)
| STATS failed_accounts = COUNT_DISTINCT(CASE(failed, acct, NULL)),
        failures = COUNT(*) WHERE failed,
        succeeded_accounts = COUNT_DISTINCT(CASE(succeeded, acct, NULL)),
        first_failure = MIN(CASE(failed, @timestamp, NULL)),
        last_success = MAX(CASE(succeeded, @timestamp, NULL)),
        success_sample = MV_SLICE(VALUES(CASE(succeeded, acct, NULL)), 0, 5),
        failed_sample = MV_SLICE(VALUES(CASE(failed, acct, NULL)), 0, 5),
        dest_hosts = MV_SLICE(VALUES(winlog.computer_name), 0, 5)
    BY source.ip
// Baseline: 10 failed accounts is I05's spray threshold. A spray that lands produces one to three successes; a
// terminal server or a NAT address where ten people mistyped also produces dozens of successes, so the upper bound
// on successes is what separates them. Measure both with the baseline query before enabling.
| WHERE failed_accounts >= 10
  AND succeeded_accounts >= 1 AND succeeded_accounts <= 3
  AND last_success >= first_failure
| SORT failed_accounts DESC
| LIMIT 50
```

## Before turning it on

Size both thresholds against your own sources:

```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE @timestamp >= NOW() - 14 days AND event.code IN ("4625", "4771", "4624") AND source.ip IS NOT NULL
| EVAL acct = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
       failed = event.code == "4625" OR (event.code == "4771" AND winlog.event_data.Status == "0x18")
| STATS failed_accounts = COUNT_DISTINCT(CASE(failed, acct, NULL)),
        succeeded_accounts = COUNT_DISTINCT(CASE(NOT failed, acct, NULL))
    BY source.ip, BUCKET(@timestamp, 1 hour)
// second STATS: turns the per-source, per-hour counts into the percentiles the threshold is set from
| STATS p95_failed = PERCENTILE(failed_accounts, 95), p99_failed = PERCENTILE(failed_accounts, 99),
        max_failed = MAX(failed_accounts)
```

The second `STATS` turns per-hour counts into the percentiles the threshold is set from. Sources that sit above the
p99 every day are shared hosts (Citrix, RD gateways, Exchange). Exclude them as entity pairs, never the whole range.

## What it misses

- A spray spread across many source addresses, so no single address reaches ten accounts. `S15`'s
  client-fingerprint approach is the answer in Entra. On-premises, there is no equivalent field.
- A success whose source address is a different host from the failures, for example a spray from one box and the
  use of the found password from another.

## When it fires

The `success_sample` accounts are the ones to act on. Reset their passwords and revoke their sessions. Then pull
everything those accounts did from the source address after `last_success`.
