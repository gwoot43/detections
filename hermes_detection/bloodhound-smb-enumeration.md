# BloodHound / SharpHound SMB enumeration

SharpHound's collection is four RPC calls, each opening its own named pipe on `\\host\IPC$`: `Session` uses `NetSessionEnum` over **srvsvc**, `LoggedOn` uses `NetWkstaUserEnum` over **wkssvc**, `LocalAdmin` uses `NetLocalGroupGetMembers` (SAMR) over **samr**, and remote-registry logons use `RegEnumKeyW` over **winreg**. The host being interrogated logs each one as a **5145**, naming the pipe, the account and the client - so the collection is visible from the target side, over NTLM or Kerberos alike, which a Kerberos ticket count is not. The fingerprint is one account using **two or more of those interfaces across ten or more hosts inside fifteen minutes**: a `net view \\host` sweep, an inventory script or a monitoring agent uses a single interface. This is the metadata side only - reading files is Snaffler's shape (certipy 10), `svcctl`/`atsvc`/`remcom_*` are remote execution (15), and the LDAP half is the ACL rule beside this one. `GPOLocalGroup` is the exception worth knowing: it reads `GptTmpl.inf` from **SYSVOL**, a data share, so that method lands in share telemetry, not here. Needs **Audit Detailed File Share** on every host you want to count; run every 5 minutes over the last 15, suppress by `user.name` for 6h.

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
// Both fields, so the same account driven from anywhere else still alerts.
  AND NOT (user.name == "<inventory_account>" AND source.ip == "<inventory_ip>")
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user"))
// One row per account: how many hosts it touched, and how many different interfaces it used.
| STATS hosts = COUNT_DISTINCT(host.name),
        pipes = COUNT_DISTINCT(winevt.event_data.relative_target_name),
        pipes_seen = MV_SLICE(VALUES(winevt.event_data.relative_target_name), 0, 4),
        addrs = COUNT_DISTINCT(source.ip),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 10 hosts and 2 interfaces in 15 minutes are starting values - a collection run reaches hundreds of hosts
// and three interfaces, an admin working by hand does neither. Measure your own p99 before tuning.
| WHERE hosts >= 10 AND pipes >= 2
| SORT hosts DESC
| LIMIT 100
```

## References

- Compass Security, *BloodHound Inner Workings & Limitations* parts 1-3 - a Wireshark trace per pipe open (`NetLocalGroupGetMembers` → `\PIPE\samr`, `NetWkstaUserEnum` → `\PIPE\wkssvc`, `NetSessionEnum` → `\PIPE\srvsvc`): `blog.compass-security.com/2022/05/bloodhound-inner-workings-part-1` and `-part-2`
- iPurple, *SharpHound Detection* (2024) - API-to-pipe table (`RegEnumKeyW` → `winreg`), 5140/5145 usage including the SYSVOL case: `ipurple.team/2024/07/15/sharphound-detection`
- SpecterOps, *SharpHound target selection and API usage*: `specterops.io/blog/2018/03/05/sharphound-target-selection-and-api-usage`
- Microsoft, event 5145 schema - `ShareName` rendered as `\\*\<share>`, `RelativeTargetName`, `ObjectType`
- SigmaHQ rule `52d8b0c6` - first-time-seen remote named pipe, keyed on `ShareName: \\*\IPC$`
- Schwartz, *From Code to Coverage* (TROOPERS26) - BloodHound/SOAPHound/Impacket detection stack: `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
