# BloodHound / SharpHound SMB enumeration

SharpHound's collection is four RPC calls, each opening its own named pipe on `\\host\IPC$` - `NetSessionEnum` (srvsvc), `NetWkstaUserEnum` (wkssvc), `NetLocalGroupGetMembers` (samr), remote-registry logons (winreg) - and **it never reads a file**. So the behaviour is: an account opening IPC$ across the estate and opening **no data share at all**. That is the mirror image of the Snaffler rule, which needs data shares on 20+ hosts, and the two cannot collide: Snaffler is `share_name NOT IN (\\*\IPC$, \\*\SYSVOL, \\*\NETLOGON)` and a share/host count; this is IPC$ only, and it requires the data-share count to be **zero** for the same account in the same window. The SYSVOL exclusion falls out for free - a `GPOLocalGroup` read is a data-share open, so it fails the zero test by design (certipy 10 covers that shape). 5145, which named the pipe itself, stopped ingesting here, so this works from 5140. If your FDR feed carries `SmbClientNamedPipeConnectEtw`, the second query is better: the pipe name says *which* collection method ran, and it carries the process.

```esql
FROM logs-yourorg-microsoft-windows*
// 5140 = a network share was opened. Every SMB session opens IPC$ first, so the count only means
// something when it is read against what else the same account opened.
| WHERE event.code == "5140"
// Machine accounts open IPC$ on every host they manage - monitoring, backup, inventory agents - and
// nothing in the event says "machine account", so this is a leading-wildcard test on purpose
  AND (user.name IS NULL OR NOT user.name LIKE "*$")
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user")),
// Triple quotes on purpose: a normal string eats one backslash level, and LIKE then sees an escape
// character that is not followed by a wildcard and errors out.
       touched_ipc = winevt.event_data.share_name LIKE """*\\IPC$"""
// Conditional aggregates: if your version rejects COUNT_DISTINCT(...) WHERE, split into two STATS on
// this flag - the logic is the same, it just costs a second pass.
| STATS ipc_hosts = COUNT_DISTINCT(host.name) WHERE touched_ipc,
        data_share_opens = COUNT(*) WHERE NOT touched_ipc,
        shares_seen = MV_SLICE(VALUES(winevt.event_data.share_name), 0, 5),
        addrs = COUNT_DISTINCT(source.ip),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 20 hosts' IPC$ and not one data share: the account interrogated the estate without reading a file.
// A collection run reaches hundreds of hosts; an admin or scanner that does this reads something. Measure
// your own p99 before tuning, and expect user-account inventory scripts in the baseline's top rows.
| WHERE ipc_hosts >= 20 AND data_share_opens == 0
| SORT ipc_hosts DESC
| LIMIT 100
```

`shares_seen` should be `\\*\IPC$` and nothing else when this fires - if anything else is in there, the `data_share_opens` count is wrong for your pipeline and the rule is passing on a parsing gap rather than on behaviour. Worth checking once.

## Better source, if Falcon has it
`SmbClientNamedPipeConnectEtw` comes from the collector's own sensor: no audit policy, and it names the pipe, so the alert says whether this was sessions, logged-on users, local admins or the registry. Verify the event and the two field names with the probe below.
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "smbclientnamedpipeconnectetw"
// The collection interfaces
  AND data.PipeName IN ("srvsvc", "samr", "wkssvc", "winreg")
// Machine accounts run these pipes as normal service traffic, and nothing in the event says "machine
// account", so this is a leading-wildcard test on purpose
  AND (data.UserName IS NULL OR NOT data.UserName LIKE "*$")
| STATS hosts = COUNT_DISTINCT(destination.ip),
        pipes = COUNT_DISTINCT(data.PipeName),
        pipes_seen = MV_SLICE(VALUES(data.PipeName), 0, 4),
        procs = MV_SLICE(VALUES(data.ContextBaseFileName), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.name
// 10 hosts and 2 interfaces in 15 minutes - SharpHound reaches hundreds of hosts and three interfaces,
// an inventory script uses one. Measure your own p99 before tuning.
| WHERE hosts >= 10 AND pipes >= 2
| SORT hosts DESC
| LIMIT 100
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// leading wildcard on purpose: this probes for event names, it is not a detection
| WHERE event.action LIKE "*pipe*"
| STATS n = COUNT(*) BY event.action
| SORT n DESC
| LIMIT 20
```

## What this is not
- **Not Snaffler** - files on data shares, and this rule requires that count to be zero. certipy 10.
- **Not remote execution** - `svcctl`/`atsvc`/`remcom_*` are certipy 15.
- **Not the LDAP half** - `-c DCOnly`, `bloodhound.py` and ADExplorer open no share; `ldap-security-descriptor-enumeration.md` covers that, certipy 24 the fan-out across DCs.
- **Not a 5145 rule** - that version named the pipe on the target and matched `relative_target_name`; it is in the branch history and comes back if Detailed File Share is ever re-enabled.

## References

- Compass Security, *BloodHound Inner Workings & Limitations* parts 1-3 - Wireshark trace of each pipe open: `blog.compass-security.com/2022/05/bloodhound-inner-workings-part-1` and `-part-2`
- iPurple, *SharpHound Detection* (2024) - API-to-pipe table (`RegEnumKeyW` → `winreg`), 5140/5145 usage including the SYSVOL case: `ipurple.team/2024/07/15/sharphound-detection`
- SpecterOps, *SharpHound target selection and API usage*: `specterops.io/blog/2018/03/05/sharphound-target-selection-and-api-usage`
- Microsoft, event 5140/5145 schemas - `ShareName` as `\\*\<share>`, `RelativeTargetName`
- Schwartz, *From Code to Coverage* (TROOPERS26): `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
