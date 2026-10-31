# BloodHound / SharpHound SMB enumeration — Falcon share events (blocked on field names)

**Status: do not deploy yet.** The idea is right and the event exists, but this event in our pipeline carries neither `data.ContextBaseFileName` nor `data.ShareName`, and without the share field the rule cannot do the one thing that makes it BloodHound rather than Snaffler: tell an IPC$ metadata sweep apart from data-share hunting. As written below it would fire on both.

Two facts already established:
- **No process context.** `SmbClientShareOpenedEtw` has no `ContextBaseFileName`, so the entity is account + host, exactly as in the 5140 rule. Attribution to a binary stays with the Falcon process pivot.
- **No `data.ShareName`.** Whatever field holds the share is named something else in this pipeline, or the event does not carry it at all.

Find out which, with one query. Run it in Discover with the free-text bar set to the token rather than a field name - KQL searches every field, so it lands on the document whichever field holds `IPC$`:
```
event.action : "smbclientshareopenedetw" and *IPC*
```
Then open one hit's JSON. Two things to read off it: the field carrying the share (`\\*\IPC$`), and the field naming the peer or remote address. If no share appears in the document at all, this event is share-agnostic and unusable for this detection - stop here and keep the 5140 rule plus the 4662 correlation.

## Template, once the two field names are known
Swap `data.ShareName` and `data.ServerName` for the real names; nothing else changes. `*IPC$` with no backslash is deliberate - a literal one needs a second escape level and trips ES|QL's escape error.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Sensor-side share opens: this fires on the machine that opened the share, so it needs no audit policy
| WHERE event.action == "smbclientshareopenedetw"
// Machine accounts open IPC$ on every host they manage - monitoring, backup, inventory agents - and
// nothing in the event labels them, so this is a leading-wildcard test on purpose
  AND (user.name IS NULL OR NOT user.name LIKE "*$")
| STATS ipc_peers = COUNT_DISTINCT(data.ServerName) WHERE data.ShareName LIKE "*IPC$",
        data_share_opens = COUNT(*) WHERE NOT data.ShareName LIKE "*IPC$",
        shares_seen = MV_SLICE(VALUES(data.ShareName), 0, 5),
        sample_peers = MV_SLICE(VALUES(data.ServerName), 0, 10),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.name, user.name
// 20 peers of IPC$ and not one data share: the account interrogated the estate without reading a file.
// A collection run reaches hundreds of peers; a scanner or inventory script reads something. Baseline it.
| WHERE ipc_peers >= 20 AND data_share_opens == 0
  AND DATE_DIFF("second", first_seen, last_seen) <= 600
| SORT ipc_peers DESC
| LIMIT 100
```

## Where the other sources stand
- **5140** (target side, `bloodhound-smb-enumeration.md`): deployable today, and the version to run until this one is unblocked. It has the share field by definition and the account, and its zero-data-share condition is what keeps it off Snaffler.
- **5145** (pipe names - srvsvc/wkssvc/samr/winreg): the highest fidelity of the three, because the pipe says which collection method ran. Not ingesting here.
- **Falcon pipe events** (`SmbClientNamedPipeConnectEtw`): not present in this feed - only the share ones are (`smbclientshareopenedetw`, `smbclientshareclosedetw`, `smbservershareopenedetw`, `smbclientsharelogonbruteforce*`).
- **4662 correlation** (the ACL-read half): the strongest detector we have, because 4662 observes the read and 5140 observes the sweep - see the top query in `bloodhound-smb-enumeration.md`.

## References

- iPurple, *SharpHound Detection* (2024) - API-to-pipe table, 5140/5145 usage: `ipurple.team/2024/07/15/sharphound-detection`
- Compass Security, *BloodHound Inner Workings* parts 1-3 - what each collection method calls: `blog.compass-security.com/2022/05/bloodhound-inner-workings-part-1`
- Schwartz, *From Code to Coverage* (TROOPERS26) - why network-side telemetry alone cannot see directory collection: `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
