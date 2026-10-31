# BloodHound / SharpHound SMB enumeration — Falcon share events

Same detection as the 5140 rule, taken from the **collector's own sensor** instead of the target's audit policy: `SmbClientShareOpenedEtw` fires on the machine that opens the share, so it works on every managed host with no *Audit File Share* requirement, and it cannot be turned off by a GPO that clears the audit policy. The behaviour is unchanged - an account opening IPC$ across the estate and opening **no data share at all**, which is the mirror image of the Snaffler rule (data shares on many hosts, certipy 10) and stays clear of it by construction.

Two things about this event before you deploy, because they change the shape of the rule:

- **There is no process context.** Unlike the pipe events, this one does not carry `ContextBaseFileName`, so the entity is the **account + host**, exactly as it is in the 5140 version. Do not try to attribute it to a binary here - the Falcon pivot does that.
- **The field names are placeholders.** The probe below prints one raw event; put the real share and peer fields into the two `data.*` names below and nothing else changes.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// Client-side share opens: this fires on the machine that opened the share, not the one sharing it.
| WHERE event.action == "smbclientshareopenedetw"
// Machine accounts open IPC$ on every host they manage - monitoring, backup, inventory agents - and
// nothing in the event labels them, so this is a leading-wildcard test on purpose
  AND (user.name IS NULL OR NOT user.name LIKE "*$")
// Conditional aggregates on the share field, so the "reads nothing" half of the behaviour is measured in
// the same pass. If your version rejects COUNT_DISTINCT(...) WHERE, split into two STATS on this flag.
| STATS ipc_peers = COUNT_DISTINCT(data.ServerName) WHERE data.ShareName LIKE "*IPC$",
        data_share_opens = COUNT(*) WHERE NOT data.ShareName LIKE "*IPC$",
        shares_seen = MV_SLICE(VALUES(data.ShareName), 0, 5),
        sample_peers = MV_SLICE(VALUES(data.ServerName), 0, 10),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.name, user.name
// 20 peers of IPC$ and not one data share: the account interrogated the estate without reading a file.
// A collection run reaches hundreds of peers; a scanner or an inventory script reads something. Measure
// your own p99 before tuning.
| WHERE ipc_peers >= 20 AND data_share_opens == 0
  AND DATE_DIFF("second", first_seen, last_seen) <= 600
| SORT ipc_peers DESC
| LIMIT 100
```

Lock the field names with this first - it prints a single raw event with every column the pipeline maps, which is all you need:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "smbclientshareopenedetw"
| SORT @timestamp DESC
| LIMIT 1
```
The two names to look for are the **share** (`ShareName`, `Share`, `TreeConnect`) and the **remote host** (`ServerName`, `RemoteAddress`, `destination.ip`). Swap them in the query - the rest of the logic does not depend on which they are. `user.name` is worth checking at the same time; if the event has no account either, group by `host.name` alone and compare the peers count against the host's own baseline instead.

## Why not the other two sources
- **5140** (target side, `hermes_detection/bloodhound-smb-enumeration.md`): names the pipe's parent share and the account, but only on hosts where *Audit File Share* is on, and the rule has to run that half from Windows events. Keep it if you have 5140 everywhere; this one is the coverage play when you don't.
- **5145** (pipe names - srvsvc/wkssvc/samr/winreg): the highest fidelity of the three, because the pipe says which collection method ran. Not ingesting here, and FDR offers no named-pipe event, so it is unavailable.

## References

- iPurple, *SharpHound Detection* (2024) - the API-to-pipe table and the 5140/5145 split: `ipurple.team/2024/07/15/sharphound-detection`
- Compass Security, *BloodHound Inner Workings* parts 1-3 - what each collection method actually calls: `blog.compass-security.com/2022/05/bloodhound-inner-workings-part-1`
- Schwartz, *From Code to Coverage* (TROOPERS26) - why network-side telemetry alone is not enough for directory collection: `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
