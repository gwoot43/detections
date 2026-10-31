# BloodHound / SharpHound SMB enumeration

SharpHound's collection is four RPC calls, each opening its own named pipe on `\\host\IPC$`: `Session` uses `NetSessionEnum` over **srvsvc**, `LoggedOn` uses `NetWkstaUserEnum` over **wkssvc**, `LocalAdmin` uses `NetLocalGroupGetMembers` (SAMR) over **samr**, and remote-registry logons use `RegEnumKeyW` over **winreg**. On the target that is a **5145** naming the pipe, the account and the client - the best view there is, and the one this rule was built on - but 5145 has not been ingesting here for eight months, so the rule below works from Falcon instead: **one host fanning out over SMB to ten or more destinations while also talking to a directory server**, which is the same collection seen from the collector's own sensor. It is lower fidelity than the pipe version because FDR shows the TCP connection, not which pipe was opened, and it only sees managed hosts. If 5145 comes back, deploy the second query too: it names the collection method outright. The pair with the LDAP half (`ldap-security-descriptor-enumeration.md`) is deliberate - this catches the SMB sweep, that one the directory read, and `-c DCOnly` only produces the latter.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// SMB fan-out plus a directory connection from the same host. SharpHound's collection is exactly that
// pair: a connect to each host's 445, and LDAP/GC/ADWS to a DC from the same machine.
| WHERE event.action == "networkconnectip4"
  AND destination.port IN (445, 389, 636, 3268, 3269, 9389)
| STATS smb_hosts = COUNT_DISTINCT(destination.ip) WHERE destination.port == 445,
        dir_conns = COUNT(*) WHERE destination.port != 445,
        procs = MV_SLICE(VALUES(data.ContextBaseFileName), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.name
// 10 SMB destinations and at least one directory connection in the window is a starting value: routine
// file-server and backup traffic does one or the other, not both at that rate. Measure your own p99.
| WHERE smb_hosts >= 10 AND dir_conns >= 1
| SORT smb_hosts DESC
| LIMIT 100
```

Two things to check in your own data before trusting it. First, whether FDR carries the **client-side share event**, which would be the real replacement for 5145 - it names the share opened (`\\host\IPC$`), and unlike 5145 it also carries the process:

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action LIKE "smbclient*" OR event.action LIKE "smbserver*"
| STATS n = COUNT(*) BY event.action
| SORT n DESC
| LIMIT 20
```
If `smbclientshareopenedetw` appears there, build the detection on it instead: group by host, count distinct remote hosts with share `\\*\IPC$`, and you have the 5145 rule back with a process name attached.

Second, the FP this shape carries: a **backup or management server** legitimately opens SMB to many hosts and talks to a DC in the same window. That is the account/host pair to exclude, and it should show up at the top of a 7-day run at a lower threshold (`smb_hosts >= 5`).

## If 5145 starts ingesting again
The pipe-level rule, which is the high-fidelity one - same account, two or more interfaces, ten or more hosts, fifteen minutes:

```esql
FROM logs-yourorg-microsoft-windows*
// 5145 on IPC$ = a named pipe was opened. These are the directory-enumeration interfaces:
// srvsvc = sessions, wkssvc = logged-on users, samr = local group members, winreg = registry.
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
| WHERE hosts >= 10 AND pipes >= 2
| SORT hosts DESC
| LIMIT 100
```

## What this is not
- **Not Snaffler** - it reads files on real shares and touches none of these pipes. That is certipy 10.
- **Not remote execution** - `svcctl`/`atsvc`/`remcom_*` belong to certipy 15.
- **Not the LDAP half** - `-c DCOnly`, `bloodhound.py` and ADExplorer open no pipe and make no SMB sweep; `ldap-security-descriptor-enumeration.md` covers that, and certipy 24 covers network fan-out across DCs.

## References

- Compass Security, *BloodHound Inner Workings & Limitations* parts 1-3 - Wireshark trace of each pipe open: `blog.compass-security.com/2022/05/bloodhound-inner-workings-part-1` and `-part-2`
- iPurple, *SharpHound Detection* (2024) - API-to-pipe table (`RegEnumKeyW` → `winreg`), 5140/5145 usage including the SYSVOL case: `ipurple.team/2024/07/15/sharphound-detection`
- SpecterOps, *SharpHound target selection and API usage*: `specterops.io/blog/2018/03/05/sharphound-target-selection-and-api-usage`
- Microsoft, event 5145 schema - `ShareName` rendered as `\\*\<share>`, `RelativeTargetName`, `ObjectType`
- Schwartz, *From Code to Coverage* (TROOPERS26) - BloodHound/SOAPHound/Impacket coverage, and the `nltest /dbflag:0x2080ffff` netlogon technique: `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
