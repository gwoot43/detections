# BloodHound / SharpHound SMB enumeration

SharpHound's collection is four RPC calls, each opening its own named pipe on `\\host\IPC$`: `Session` uses `NetSessionEnum` over **srvsvc**, `LoggedOn` uses `NetWkstaUserEnum` over **wkssvc**, `LocalAdmin` uses `NetLocalGroupGetMembers` (SAMR) over **samr**, and remote-registry logons use `RegEnumKeyW` over **winreg**. **The pipe name is the whole detection** - Snaffler reads files on data shares and opens none of these, so a rule keyed on the pipe separates the two tools by construction; a rule keyed on "one host connecting to SMB on many hosts" cannot, because both tools do exactly that. With 5145 gone from the feed, the source to build on is Falcon's own client-side pipe event (`SmbClientNamedPipeConnectEtw`), which is arguably better than 5145 was: it comes from the collector's sensor, needs no audit policy, and carries the process. Verify the two field names with the probe below before deploying - the pipe field is `data.PipeName` in the usual FDR mapping, but this is an ETW-derived event and the mapping is the one thing I could not confirm from public sources.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// Falcon's client-side named-pipe event: the collector's sensor records the pipe it opened and the host.
| WHERE event.action == "smbclientnamedpipeconnectetw"
// The collection interfaces. Verify the field name with the probe below before trusting this.
  AND data.PipeName IN ("srvsvc", "samr", "wkssvc", "winreg")
// Machine accounts run these pipes as normal service traffic - monitoring, backup, inventory agents
  AND (data.UserName IS NULL OR NOT data.UserName LIKE "*$")
| STATS hosts = COUNT_DISTINCT(destination.ip),
        pipes = COUNT_DISTINCT(data.PipeName),
        pipes_seen = MV_SLICE(VALUES(data.PipeName), 0, 4),
        procs = MV_SLICE(VALUES(data.ContextBaseFileName), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.name
// 10 hosts and 2 interfaces in 15 minutes are starting values - SharpHound reaches hundreds of hosts and
// three interfaces, an inventory script uses one. Measure your own p99 before tuning.
| WHERE hosts >= 10 AND pipes >= 2
| SORT hosts DESC
| LIMIT 100
```

Before deploying, confirm the event and its fields in your own feed - this prints one raw row per pipe-event name, which is all you need to fix the field names:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action LIKE "*pipe*"
| STATS n = COUNT(*) BY event.action
| SORT n DESC
| LIMIT 20
```
If `smbclientnamedpipeconnectetw` is not there, the fallbacks in order are `smbclientshareopenedetw` (names the share - `\\host\IPC$` - but not the pipe), then 5145 below, then nothing: do **not** fall back to a TCP fan-out on 445, which fires on Snaffler's share sweep as readily as on a collection run.

Why the account filter matters: agents run as machine accounts and open the same pipes to every host they manage, so without the `$` exclusion the rule is a mirror of your monitoring product.

## If 5145 starts ingesting again
Same logic from the target side - no process name, but the pipe and the account, on the host that was interrogated:
```esql
FROM logs-yourorg-microsoft-windows*
// 5145 on IPC$ = a named pipe was opened. srvsvc = sessions, wkssvc = logged-on users,
// samr = local group members, winreg = registry.
| WHERE event.code == "5145"
// Leading wildcard on purpose: ShareName is logged as \\*\IPC$ with the server masked, so there is no
// prefix to index. If your pipeline lowercases it, add the lowercase variant of this pattern.
  AND winevt.event_data.share_name LIKE "*\\IPC$"
  AND winevt.event_data.relative_target_name IN ("srvsvc", "samr", "wkssvc", "winreg")
// Machine accounts run these pipes as normal service traffic, and nothing in 5145 says "machine account",
// so this is a leading-wildcard test on purpose. IS NULL keeps a row whose subject is missing.
  AND (user.name IS NULL
       OR (NOT user.name LIKE "*$" AND NOT user.name LIKE "*$@*"))
// Sanctioned inventory / monitoring account, as an account + address pair (placeholders, repeat per pair).
  AND NOT (user.name == "<inventory_account>" AND source.ip == "<inventory_ip>")
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user"))
| STATS hosts = COUNT_DISTINCT(host.name),
        pipes = COUNT_DISTINCT(winevt.event_data.relative_target_name),
        pipes_seen = MV_SLICE(VALUES(winevt.event_data.relative_target_name), 0, 4),
        addrs = COUNT_DISTINCT(source.ip),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 10 hosts and 2 interfaces in 15 minutes - the same starting values, measure your own p99
| WHERE hosts >= 10 AND pipes >= 2
| SORT hosts DESC
| LIMIT 100
```

## What this is not
- **Not Snaffler** - it reads files on real shares and opens none of these pipes. That is certipy 10, and the pipe name is why the two rules cannot collide.
- **Not remote execution** - `svcctl`/`atsvc`/`remcom_*` belong to certipy 15.
- **Not the LDAP half** - `-c DCOnly`, `bloodhound.py` and ADExplorer open no pipe; `ldap-security-descriptor-enumeration.md` covers that, and certipy 24 covers network fan-out across DCs.

## References

- Compass Security, *BloodHound Inner Workings & Limitations* parts 1-3 - Wireshark trace of each pipe open: `blog.compass-security.com/2022/05/bloodhound-inner-workings-part-1` and `-part-2`
- iPurple, *SharpHound Detection* (2024) - API-to-pipe table (`RegEnumKeyW` → `winreg`), 5140/5145 usage including the SYSVOL case: `ipurple.team/2024/07/15/sharphound-detection`
- SpecterOps, *SharpHound target selection and API usage*: `specterops.io/blog/2018/03/05/sharphound-target-selection-and-api-usage`
- Microsoft, event 5145 schema - `ShareName` as `\\*\<share>`, `RelativeTargetName`, `ObjectType`
- Schwartz, *From Code to Coverage* (TROOPERS26) - the LDAP/SOAPHound side and the netlogon technique: `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
