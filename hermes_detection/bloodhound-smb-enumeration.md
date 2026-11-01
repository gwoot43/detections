# BloodHound / SharpHound collection — the SMB half, from 5140 alone

SharpHound's estate enumeration is four RPC calls - `NetSessionEnum` (srvsvc), `NetWkstaUserEnum` (wkssvc), `NetLocalGroupGetMembers` (samr), remote-registry logons (winreg) - and every one of them rides a pipe on `\\host\IPC$`. It opens pipes and reads **no file**. That is the signature this rule keys on, and it survives every telemetry loss in this estate, which is why it is now the primary detection rather than a fallback.

Three losses removed the more precise versions, and the rule is shaped by them:
- **5145 (Detailed File Share)** would name the pipe itself - `srvsvc`, `samr`, `winreg`, `lsarpc` - and turn this from a breadth test into a method test. It stopped ingesting eight months ago, and `relative_target_name` was never recorded at all.
- **4662 with `0x10`/`0x100`** would show the ACL reads coming back from the DC, which is the other half of the same run. Those masks are not written (see `ldap-directory-reach.md`).
- **Falcon** has no pipe event in this feed, and its share events (`smbclientshareopenedetw`) carry no `ShareName`, so neither can separate an IPC$ sweep from share hunting.

What remains is one event, one index, one reduce - and an **absence condition** that does the work the pipe name used to do.

```esql
FROM logs-yourorg-microsoft-windows*
// 30-minute window stated in the query - the rule settings alone let an analyst reopen this over a day and
// turn it into a different rule.
| WHERE @timestamp >= NOW() - 30 minutes
  AND event.code == "5140"
// Machine accounts open IPC$ on every host they manage, and nothing in 5140 says "machine account", so this
// is a leading-wildcard test on purpose.
  AND (user.name IS NULL OR NOT user.name LIKE "*$")
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user")),
// No backslash in the pattern: a literal one needs a second escape level and trips ES|QL's "escape character
// not followed by a wildcard" error. ShareName always ends in \IPC$.
       touched_ipc = winevt.event_data.share_name LIKE "*IPC$"
// One row per account: how many hosts it opened IPC$ on, and how many *other* shares it opened.
| STATS ipc_hosts = COUNT_DISTINCT(host.name) WHERE touched_ipc,
        data_share_opens = COUNT(*) WHERE NOT touched_ipc,
        shares_seen = MV_SLICE(VALUES(winevt.event_data.share_name), 0, 5),
        addrs = COUNT_DISTINCT(source.ip),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 20 hosts of IPC$ with no data share opened, and the whole sweep inside ten minutes. The absence of data
// shares is what removes Snaffler and every file-hunting tool by construction - they read files on data
// shares and never open these pipes. The rate is what removes an admin working through a list.
| WHERE ipc_hosts >= 20 AND data_share_opens == 0
  AND DATE_DIFF("second", first_seen, last_seen) <= 600
| SORT ipc_hosts DESC
| LIMIT 100
```

Deploy every 15 minutes over the last 30. Suppress by `user.name` for 6h.

## Reading the alert
- **`ipc_hosts`** is the breadth of the sweep. SharpHound's default session and registry collection hits every host it can resolve, so a real run is hundreds; 20 is the starting value.
- **`data_share_opens == 0`** is the discriminator, not a filter. A single data-share open means the account was after files, which is Snaffler's story (`share-hunting-snaffler.md`) and a different triage path.
- **`addrs`** above 1 is worth a look: SharpHound run through a proxy or from a relay host shows two addresses, a direct run shows one.
- **`shares_seen`** should be `\\*\IPC$` and nothing else. Anything unexpected there means the absence condition was satisfied by luck rather than by shape.

## Nearest benign twins
- **Inventory and vulnerability scanners** that authenticate and touch IPC$ on every host. They normally also open one data or management share somewhere; when they don't, they are indistinguishable from this rule and belong in an entity-pair exclusion keyed on the scanner account **and** its scanner address.
- **Admin scripts** that loop over a host list. The 10-minute span is the discriminator: a person working a list finishes 20 hosts over an hour, not in four minutes.
- **Backup and monitoring agents** run as machine or service accounts and are removed by the `$` exclusion.

## What it misses
- **The method.** Without pipe names this cannot tell `NetSessionEnum` from `NetWkstaUserEnum` from a file-copy probe - only that an account opened IPC$ broadly and read no data share. That was 5145's contribution and it is gone.
- **The LDAP half.** SharpHound's directory collection is invisible here entirely (see `ldap-directory-reach.md`), so a `-c DCOnly` run produces nothing at all.
- **A small, targeted collection.** 20 hosts is a starting value; a run against the ten hosts that matter stays under it.
- **Encrypted or proxied SMB**, and targets whose Audit File Share is off - the event is written on the target, so a target without auditing caps the count.
- **SharpHound run under a different account per host**, which never accumulates on one `user.name`.

## Baseline
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 7 days
  AND event.code == "5140"
  AND (user.name IS NULL OR NOT user.name LIKE "*$")
  AND winevt.event_data.share_name LIKE "*IPC$"
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user")), bucket = DATE_TRUNC(1 hour, @timestamp)
| STATS ipc_hosts = COUNT_DISTINCT(host.name) BY user.name, bucket
// this is the baseline: no threshold, because filtering first would hide the accounts it exists to measure
| STATS active_hours = COUNT(*), p50 = PERCENTILE(ipc_hosts, 50), p99 = PERCENTILE(ipc_hosts, 99), peak = MAX(ipc_hosts)
    BY user.name
| SORT peak DESC
| LIMIT 50
```
An account with `p99` of one or two hosts and a `peak` in the hundreds is a sweep. An account with a `peak` in the hundreds every hour is a scanner: an entity pair, not a bigger threshold.

## If the telemetry comes back
5145 with `relative_target_name` restores the method test, and it is the version to prefer: `srvsvc`/`samr`/`wkssvc`/`winreg` on IPC$ is enumeration by name, with no rate tuning at all. Probe before assuming it is still off:
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "5145"
| STATS n = COUNT(*), last = MAX(@timestamp) BY winevt.event_data.relative_target_name
| SORT n DESC
| LIMIT 25
```
An empty result, or a `last` older than a week, means the audit subcategory is still off. Same check for Falcon pipe events: `FROM logs-yourorg-crowdstrike-data-default* | WHERE event.action LIKE "*pipe*" | STATS n = COUNT(*) BY event.action`.

## References
- Compass Security, *BloodHound Inner Workings & Limitations* parts 1-3 - the Wireshark trace showing one pipe per API: `blog.compass-security.com/2022/05/bloodhound-inner-workings-part-1`
- iPurple, *SharpHound Detection* (2024) - API-to-pipe table, and the 5140/5145 approach this rule was reduced from: `ipurple.team/2024/07/15/sharphound-detection`
- SpecterOps, *SharpHound target selection and API usage* - why the default sweep is broad: `specterops.io/blog/2018/03/05/sharphound-target-selection-and-api-usage`
- Microsoft, event 5140 schema - `ShareName` as `\\*\<share>`, `SubjectUserName`, `IpAddress`
- `share-hunting-snaffler.md` - the data-share mirror image; `ldap-directory-reach.md` - the attribution-side LDAP rule
