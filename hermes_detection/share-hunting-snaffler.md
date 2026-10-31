# Share hunting (Snaffler-class)

Snaffler and its imitators walk the estate looking for **readable files that hold secrets**: they open real shares (`C$`, `ADMIN$`, user and project shares), enumerate directories and read what they find. That is the opposite of BloodHound, which opens `\\host\IPC$` and reads no file - so the two rules are the mirror image of each other and cannot fire on the same activity. The exclusions are what make it precise: IPC$, SYSVOL and NETLOGON are enumeration and policy reads, not file hunting, and machine accounts open shares by design.

Deployable as-is on 5140 (*Audit File Share* on the hosts you want to count). Run every 15 minutes over the last 15, suppress by `user.name` for 6h.

```esql
FROM logs-yourorg-microsoft-windows*
// 5140 = a network share was opened, logged on the host that owns it
| WHERE event.code == "5140"
// Machine accounts open shares as normal service traffic, and nothing in the event says "machine account",
// so this is a leading-wildcard test on purpose
  AND (user.name IS NULL OR NOT user.name LIKE "*$")
// IPC$, SYSVOL and NETLOGON are enumeration and policy reads, not file hunting. The wildcards are
// deliberate: the share name is only identifiable by its tail (\\*\IPC$), and a literal backslash needs a
// second escape level that trips ES|QL's escape error.
  AND (winevt.event_data.share_name IS NULL
       OR (NOT winevt.event_data.share_name LIKE "*IPC$"
           AND NOT winevt.event_data.share_name LIKE "*SYSVOL"
           AND NOT winevt.event_data.share_name LIKE "*NETLOGON"))
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user"))
// One row per account: how many different shares it opened, on how many hosts
| STATS shares = COUNT_DISTINCT(winevt.event_data.share_name),
        hosts = COUNT_DISTINCT(host.name),
        shares_seen = MV_SLICE(VALUES(winevt.event_data.share_name), 0, 5),
        hosts_seen = TOP(host.name, 10, "asc"),
        addrs = COUNT_DISTINCT(source.ip),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 20 hosts and 5 shares is the shape of a share sweep - a person opens one share on one host, and an
// inventory script reads nothing. Tune against your own baseline before shipping.
| WHERE hosts >= 20 AND shares >= 5
| SORT hosts DESC
| LIMIT 100
```

`shares_seen` is the triage detail: `C$`/`ADMIN$` across many hosts is an administrative sweep, project and user shares across many hosts is data hunting. If `SYSVOL` or `NETLOGON` show up in `shares_seen`, the exclusions are not matching your share-name casing and the rule is one edit from being your Snaffler rule again.

## Relationship to the other two detections
- **BloodHound** (`bloodhound-smb-enumeration.md`) - IPC$ only, and zero data shares in the same window. Disjoint by construction: this rule requires a data share, that one requires none.
- **AD ACL reads** (`ldap-security-descriptor-enumeration.md`) - the directory half of collection, on the DC. Snaffler never touches it, so there is no overlap there either.
- SYSVOL reads land here rather than in the BloodHound rule, which is correct: `GPOLocalGroup` collection is a policy-file read over a data share.

## References

- Black Hills Information Security, *Snaffler* - what the tool reads and the share list it walks: `github.com/SnaffCon/Snaffler`
- iPurple, *SharpHound Detection* (2024) - the 5140/5145 split and why IPC$/SYSVOL/NETLOGON are excluded from file-hunting rules: `ipurple.team/2024/07/15/sharphound-detection`
- Microsoft, event 5140 schema - `ShareName` as `\\*\<share>`, `IpAddress`, `SubjectUserName`
