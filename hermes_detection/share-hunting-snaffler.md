# Share hunting (Snaffler-class)

Snaffler and its imitators look for **readable files that hold secrets**: they open real shares, walk directories, and read whatever they find. The behaviour is breadth - many shares, on many hosts, in minutes - and the tell is that the account reads data it has no relationship with.

This rule is the **data-share** half of AD collection, and the boundary with its neighbours is deliberate:
- **BloodHound** (`bloodhound-smb-enumeration.md`) opens `IPC$` and **no data share at all**; this rule requires the opposite, so the two cannot fire on the same activity.
- **Admin-share sweeps** (`C$`, `ADMIN$`) belong to certipy 14/15 - they are access, not file hunting. `hidden_shares` separates them without a second rule.
- **SYSVOL** reads are `GPOLocalGroup` collection; they are excluded here by name, and the BloodHound rule's zero-data-share condition already excludes them there.

```esql
FROM logs-yourorg-microsoft-windows*
// One hour, stated in the query - the schedule is what makes "20 computers" mean "in an hour".
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code == "5140"
  AND winevt.event_data.share_name IS NOT NULL
  AND user.name IS NOT NULL
// Machine accounts open shares as service traffic, and nothing in 5140 labels them, so wildcard on purpose
  AND NOT user.name LIKE "*$"
// IPC$ is RPC (08); SYSVOL and NETLOGON are opened at every logon. Leading-wildcard patterns on purpose -
// an exact list misses the unmasked (\\host\IPC$) or differently-cased form and the rule becomes a logon rule.
  AND NOT winevt.event_data.share_name LIKE "*IPC$"
  AND NOT winevt.event_data.share_name LIKE "*SYSVOL"
  AND NOT winevt.event_data.share_name LIKE "*NETLOGON"
| EVAL share_name = TO_LOWER(winevt.event_data.share_name),
       account = TO_LOWER(user.name),
// REPLACE is a literal replace - there is no anchor to strip, so the pattern carries none. Without this the
// v4-mapped and plain forms of one address become two entities, and the address exclusions below miss one.
       ip = REPLACE(TO_STRING(source.ip), "::ffff:", ""),
       share = CONCAT(TO_LOWER(host.name), " ", share_name)
| WHERE account != "anonymous logon"
// One row per account and address: the account is the actor, the address is the context that also makes the
// scanner exclusion possible.
| STATS computers = COUNT_DISTINCT(host.name),
        shares = COUNT_DISTINCT(share),
        hidden_shares = COUNT_DISTINCT(share) WHERE share_name LIKE "*$",
        sample = TOP(share, 20, "asc"),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY source.ip = ip, user.name = account
// Three conditions, because each one alone has a benign twin: one share across 20 hosts is inventory, many
// shares per host is reading, and a person spreads the same work across the hour where a tool finishes in
// minutes. 20 / 25 / 15 minutes are starting values - measure your own p99 per account below.
| EVAL span_s = DATE_DIFF("second", first_seen, last_seen)
| WHERE computers >= 20 AND shares >= 25 AND span_s <= 900
// Sanctioned scanners, backup and deployment accounts as account + address pairs (placeholders, repeat per pair)
| WHERE NOT (user.name == "<scanner_account>" AND source.ip == "<scanner_ip>")
| SORT shares DESC
| LIMIT 100
```

Deploy every 15 minutes over the last hour. Suppress by `user.name` for 6h.

## Reading the alert
- **`shares` to `computers`** is the shape: a ratio near 1 means one share per host (inventory, deployment), a ratio of 3+ means the tool opened everything readable on each box. That is the Snaffler signature.
- **`hidden_shares`** separates the stories without a second rule. Close to `shares` means the account only touched `C$`/`ADMIN$` - admin-share access, which is certipy 14/15's territory and worth a different triage path. Low `hidden_shares` with high `shares` means data shares, which is file hunting.
- **`sample`** is alphabetical, not "the worst twenty" - it is there so the analyst recognises the naming convention (user homes, project shares, `SYSVOL`-adjacent paths) without a second query.
- **`span_s`** under 900 with 20+ hosts is a burst. If it is near 3600 the run was throttled, which is a different conversation about the same actor.

## Baseline
Seven days, hourly buckets, no threshold - filtering first would hide every account whose peak sits under it:
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 7 days
  AND event.code == "5140"
  AND winevt.event_data.share_name IS NOT NULL AND user.name IS NOT NULL
// same leading-wildcard tests as the rule, for the same reasons: machine accounts, and the three shares
// that are enumeration or logon noise rather than file hunting
  AND NOT user.name LIKE "*$"
  AND NOT winevt.event_data.share_name LIKE "*IPC$"
  AND NOT winevt.event_data.share_name LIKE "*SYSVOL"
  AND NOT winevt.event_data.share_name LIKE "*NETLOGON"
| EVAL share_name = TO_LOWER(winevt.event_data.share_name), user.name = TO_LOWER(user.name),
       share = CONCAT(TO_LOWER(host.name), " ", share_name),
       bucket = DATE_TRUNC(1 hour, @timestamp)
| STATS computers = COUNT_DISTINCT(host.name), shares = COUNT_DISTINCT(share) BY user.name, bucket
// this is the baseline: no threshold here, because filtering first would hide the accounts it exists to measure
| STATS active_hours = COUNT(*),
        p50_computers = PERCENTILE(computers, 50), p99_computers = PERCENTILE(computers, 99), max_computers = MAX(computers),
        p99_shares = PERCENTILE(shares, 99), max_shares = MAX(shares)
    BY user.name
| SORT max_computers DESC
| LIMIT 50
```
An account whose `p99` is 1-2 computers and whose `max` is in the hundreds is a sweep. An account with `max_computers` 200+ every day is a scanner or a deployment product: an entity pair, not a higher threshold.

## What it misses
- **The read itself.** 5140 records the share open, not the file access - 5145 would show it and is not ingesting. A tool that opens a share and leaves looks identical here to one that greps it, so the rule detects hunting at scale, not reading.
- **Hosts where Audit File Share is off**, which caps the computer count and makes the threshold environment-specific.
- **A sweep split across accounts or addresses**, each under the threshold. The entity is the account + address pair; that case needs the destination-side view (5145, or the file-access telemetry you don't collect).
- **A quiet hunt** spread across the whole day. `span_s` deliberately excludes it; a daily rule at a lower computer count is the answer, not a wider burst window.
- **Snaffler run from an unmanaged host against servers whose 5140 you collect** - that still shows, because the event is written by the target. This is the one direction where target-side telemetry beats endpoint telemetry.

## References
- PORTS-REFERENCE (this repo) - Snaffler row, and the share-hunting entry in the behaviour section
- `certipy_detections/10` - the earlier single-signal version of this rule; this one adds the share ratio, the burst and the hidden-share label
- `bloodhound-smb-enumeration.md` - the complementary `IPC$`-only rule (disjoint by construction)
- Microsoft, event 5140 schema - `ShareName` as `\\*\<share>`, `SubjectUserName`, `IpAddress`
