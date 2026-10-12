# 06 · Kerberoasting (Windows 4769)

**Verdict before:** it works, but only for the loudest form of the attack: RC4 tickets for 10 or more services in one fixed five-minute window, counted per domain controller.
**After:** counts per requester across all DCs, uses the rule lookback instead of fixed buckets, adds a lower RC4 threshold and an any-encryption tier, and pairs it with a honey SPN check.

## Before
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "4769"
| WHERE winevt.event_data.status == "0x0"
| WHERE winevt.event_data.ticket_encryption_type == "0x17"
| WHERE NOT ENDS_WITH(winevt.event_data.service_name, "$")
| WHERE TO_LOWER(winevt.event_data.service_name) != "krbtgt"
| WHERE NOT ENDS_WITH(user.name, "$")
| EVAL time_bucket = DATE_TRUNC(5 minutes, @timestamp)
| STATS tgs_count = COUNT(*), distinct_services = COUNT_DISTINCT(winevt.event_data.service_name),
    service_names = MV_SLICE(MV_SORT(VALUES(winevt.event_data.service_name)), 0, 19),
    first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY time_bucket, source.ip, user.name, host.name
| WHERE distinct_services >= 10
| KEEP time_bucket, first_seen, last_seen, source.ip, user.name, host.name, tgs_count, distinct_services, service_names
| SORT distinct_services DESC, tgs_count DESC
| LIMIT 100
```

## What's wrong

| # | Problem | Effect |
|---|---|---|
| 1 | Grouped by `host.name`, which for 4769 is the domain controller that issued the ticket. | Requests spread across several DCs are counted separately and each stays under 10. |
| 2 | Fixed 5-minute `DATE_TRUNC` buckets. | Requests spaced out over time, or straddling a bucket edge, never reach the threshold. |
| 3 | 10 distinct services in one bucket. | Targeted requests for a handful of chosen accounts stay below it. |
| 4 | RC4 (`0x17`) only. | Requests for AES tickets (`0x12`) are not counted at all. |
| 5 | `NOT ENDS_WITH(user.name, "$")`. In 4769 the requester is often written as `host$@DOMAIN`, which doesn't end in `$`. | Computer-account requests may not be excluded. Check a sample event. |
| 6 | `SORT` and `LIMIT 100`. | No effect on a detection rule except capping alerts. Remove them. |

## After
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "4769" AND winevt.event_data.status == "0x0"
| EVAL svc = TO_LOWER(winevt.event_data.service_name),
       requester = TO_LOWER(MV_FIRST(SPLIT(user.name, "@"))),
       enc = winevt.event_data.ticket_encryption_type
| WHERE NOT ENDS_WITH(svc, "$") AND NOT STARTS_WITH(svc, "krbtgt") AND NOT ENDS_WITH(requester, "$")
| EVAL rc4_svc = CASE(enc IN ("0x17", "0x18"), svc, NULL)
| STATS services = COUNT_DISTINCT(svc), rc4_services = COUNT_DISTINCT(rc4_svc), requests = COUNT(*),
        service_list = VALUES(svc), enc_types = VALUES(enc), dcs = VALUES(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY requester, source.ip
| EVAL tier = CASE(rc4_services >= 3, "rc4 tickets for several service accounts",
                   services >= 15, "tickets for many service accounts (any encryption)",
                   NULL)
| WHERE tier IS NOT NULL
| EVAL service_list = MV_SLICE(MV_SORT(service_list), 0, 19)
```
Run every 15 minutes with a 1-hour lookback. Suppress by `requester`, `tier` for 6h.

- **Computer accounts (`$`) are removed after the `@domain` is stripped**, so the filter works whichever way your pipeline writes the requester.
- **Tune both thresholds on two weeks of history.** If legacy RC4-only service accounts make the RC4 tier noisy, set `msDS-SupportedEncryptionTypes` on those accounts. That's a hardening win in itself.
- **Once service accounts are AES-only,** drop the RC4 threshold to 1: any RC4 ticket for a user-account SPN is then worth an alert.

## Pair it with a honey SPN
A service account with an SPN that nothing uses, and a long random password. One ticket request for it is an alert, whatever the encryption and however slowly it was requested. This is library rule D01 (`rules/16-deception/`). In your field names:
```esql
FROM logs-yourorg-microsoft-windows* METADATA _id, _index, _version
| WHERE event.code == "4769" AND TO_LOWER(winevt.event_data.service_name) == "<honey_service_account>"
| KEEP @timestamp, user.name, source.ip, host.name, winevt.event_data.ticket_encryption_type, winevt.event_data.status
```

## Before vs after

| | Before | After |
|---|---|---|
| Requests spread across DCs | Split, often missed | Counted together |
| Slow requests | Missed by fixed buckets | Counted over the 1-hour lookback |
| Targeted requests (3–9 accounts) | Missed | RC4 tier at 3 |
| AES ticket requests | Not counted | Any-encryption tier at 15 |
| Single quiet request | Missed | Honey SPN |
| Computer-account requesters | May leak through | Removed after `@domain` is stripped |

## Test
Run the Atomic Red Team test for T1558.003 from a lab account. It should land in the RC4 tier, and the honey SPN rule should fire if its account is in scope.
