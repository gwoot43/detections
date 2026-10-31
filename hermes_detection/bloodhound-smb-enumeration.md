# BloodHound / SharpHound collection

A BloodHound run is **two halves in one session**: SharpHound enumerates the estate over SMB (four RPC calls - `NetSessionEnum` on srvsvc, `NetWkstaUserEnum` on wkssvc, `NetLocalGroupGetMembers` on samr, remote-registry logons on winreg - each opening a pipe on `\\host\IPC$` and **reading no file**), and it reads the directory's ACLs through LDAP. Either half alone is weak: IPC$ on many hosts is what any scanner, inventory script or admin loop does, and an ACL read is what ADUC does. **The pair, from the same account in the same window, is the run.** That correlation is the highest-fidelity version available with what we have - one index, one reduce, no lookup - and it is the rule below. The query after it is the IPC$-only fallback, for when the 4662 half is not audited in your estate.

What keeps it off Snaffler: Snaffler reads files on data shares and never opens these pipes, so the IPC$-only count plus `data_share_opens == 0` is the mirror image of that rule (certipy 10). What keeps it off your scanner: a scanner does the SMB half and not the ACL half.

```esql
FROM logs-yourorg-microsoft-windows*
// Both halves of a collection run live in this index: 5140 IPC$ opens on the targets being interrogated,
// 4662 read-property/control-access on the DC as the ACLs come back.
| WHERE (event.code == "5140" AND winevt.event_data.share_name LIKE "*IPC$")
     OR (event.code == "4662" AND winevt.event_data.access_mask IN ("0x10", "0x100"))
// Machine accounts do both by design - monitoring agents, DCs, backup, Entra Connect
  AND (user.name IS NULL OR NOT user.name LIKE "*$")
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user"))
| STATS ipc_hosts = COUNT_DISTINCT(host.name) WHERE event.code == "5140",
        acl_reads = COUNT(*) WHERE event.code == "4662",
        acl_objects = COUNT_DISTINCT(winevt.event_data.object_name) WHERE event.code == "4662",
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 10 hosts is enough here because the second half carries the precision: a scanner or an inventory
// script produces the IPC$ sweep alone. Measure both halves against your baseline before tuning.
| WHERE ipc_hosts >= 10 AND acl_reads >= 1
| SORT ipc_hosts DESC
| LIMIT 100
```

`acl_objects` is the scale of the directory read: a person checking permissions touches a handful, a collector walks thousands. If `acl_reads` is always 0 in your data, the 4662 SACL is not auditing reads - run the probe in `ldap-security-descriptor-enumeration.md`, because until it does, this query can never fire.

## Fallback: IPC$ only
For when the directory half is blind. Weaker on purpose - this is the shape a scanner also produces, so it needs a tighter rate and the no-data-share condition to stay usable.
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "5140"
// Machine accounts open IPC$ on every host they manage, and nothing in the event says "machine account",
// so this is a leading-wildcard test on purpose
  AND (user.name IS NULL OR NOT user.name LIKE "*$")
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user")),
// No backslash in the pattern: a literal one needs a second escape level and trips ES|QL's
// "escape character not followed by a wildcard" error. ShareName always ends in \IPC$.
       touched_ipc = winevt.event_data.share_name LIKE "*IPC$"
| STATS ipc_hosts = COUNT_DISTINCT(host.name) WHERE touched_ipc,
        data_share_opens = COUNT(*) WHERE NOT touched_ipc,
        shares_seen = MV_SLICE(VALUES(winevt.event_data.share_name), 0, 5),
        addrs = COUNT_DISTINCT(source.ip),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 20 hosts of IPC$ with no data share opened, and the whole sweep inside ten minutes: the rate is what
// separates a collection run from an admin working through a list. Measure your own p99 before tuning.
| WHERE ipc_hosts >= 20 AND data_share_opens == 0
  AND DATE_DIFF("second", first_seen, last_seen) <= 600
| SORT ipc_hosts DESC
| LIMIT 100
```

## If Falcon carries the pipe event
`SmbClientNamedPipeConnectEtw` would name the pipe itself - which collection method ran - from the collector's own sensor, with no audit policy needed. Check with `FROM logs-yourorg-crowdstrike-data-default* | WHERE event.action LIKE "*pipe*" | STATS n = COUNT(*) BY event.action | SORT n DESC | LIMIT 20`; if it exists, that beats both queries above because it needs no second source to be precise.

## References

- Compass Security, *BloodHound Inner Workings & Limitations* parts 1-3 - Wireshark trace of each pipe open: `blog.compass-security.com/2022/05/bloodhound-inner-workings-part-1` and `-part-2`
- iPurple, *SharpHound Detection* (2024) - API-to-pipe table (`RegEnumKeyW` → `winreg`), 5140/5145 usage including the SYSVOL case: `ipurple.team/2024/07/15/sharphound-detection`
- SpecterOps, *SharpHound target selection and API usage*: `specterops.io/blog/2018/03/05/sharphound-target-selection-and-api-usage`
- Microsoft, events 5140/4662 schemas
- Schwartz, *From Code to Coverage* (TROOPERS26) - SDFlags and the LDAP half: `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
