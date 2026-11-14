---
id: WE21
name: Local account created and added to the local Administrators group on a server (4720 then 4732)
category: windows-event-logs
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1136.001, T1098]
data_source: Windows Security 4720 and 4732 on member servers
suppression:
  fields: [host_key, acct_sid]
  duration: 24h
  missing_fields: do_not_suppress
---

A local account created on a server, then made a member of that server's own `Administrators` group, is a backdoor
that survives a domain password reset and needs no domain rights to use. `W07` sees this on the command line
(`net user /add`, `net localgroup administrators`). This rule reads the events the server itself writes. So it also
catches the account made through an API, a remote management tool or a script that never runs `net.exe`.

The pair is the anchor. Linking the `4720` (account created) to the `4732` (added to a group) by the **account SID**
means the alert is about one account, created and promoted, not two unrelated events on the same host.

Domain controllers are excluded. A `4732` to `BUILTIN\Administrators` on a DC is a domain-wide Tier-0 grant, and
`I02` owns that.

## Query

Run every 15 minutes with a 1-hour lookback.

```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code IN ("4720", "4732")
| EVAL host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, "."))),
       grp_sid = TO_UPPER(COALESCE(winlog.event_data.TargetSid, "")),
       grp_name = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
       grp_domain = TO_LOWER(COALESCE(winlog.event_data.TargetDomainName, "")),
       // 4720: TargetSid is the new account. 4732: MemberSid is the account added.
       acct_sid = TO_UPPER(COALESCE(CASE(event.code == "4720", winlog.event_data.TargetSid,
                                         winlog.event_data.MemberSid), "")),
       // SID first; the group name is the fallback because VISIBILITY-GAPS records SID fields arriving unreliably
       to_local_admins = event.code == "4732"
                         AND (grp_sid == "S-1-5-32-544" OR (grp_domain == "builtin" AND grp_name == "administrators"))
// your server naming (placeholders); drop this line to extend the rule to workstations
| WHERE host_key LIKE "srv*" OR host_key LIKE "*-srv*"
// DCs are I02's (domain-wide BUILTIN\Administrators); your DC naming
  AND NOT (host_key LIKE "dc*" OR host_key LIKE "*-dc*")
  AND acct_sid != "" AND (event.code == "4720" OR to_local_admins)
| STATS created_at = MIN(CASE(event.code == "4720", @timestamp, NULL)),
        added_at = MIN(CASE(to_local_admins, @timestamp, NULL)),
        account = MV_SLICE(VALUES(CASE(event.code == "4720", winlog.event_data.TargetUserName, NULL)), 0, 3),
        actors = MV_SLICE(VALUES(winlog.event_data.SubjectUserName), 0, 3)
    BY host_key, acct_sid
| WHERE created_at IS NOT NULL AND added_at IS NOT NULL AND added_at >= created_at
| EVAL seconds_to_admin = DATE_DIFF("second", created_at, added_at)
| SORT added_at DESC
| LIMIT 50
```

## Before turning it on

- **Server Security logs must be collected**, not only domain controllers'. Local accounts live in each server's own
  SAM, so `4720`/`4732` for them are written only on that server. Probe:

```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE @timestamp >= NOW() - 7 days AND event.code IN ("4720", "4732")
| EVAL host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, ".")))
| STATS events = COUNT(*) BY host_key, event.code
| SORT events DESC
| LIMIT 30
```

  Only DC names in the result means member servers are not forwarding Security events, and this rule cannot fire.
- Fill the server naming placeholders, or replace them with a lookup of server hostnames.

## Benign twins

- **Server builds.** An imaging or configuration-management task creates a local admin during provisioning. The actor
  is the build account, and the host is in its first day. Exclude the pair of build account and new-server window.
- **LAPS-managed accounts** are created once per server at build time. They are the same name fleet-wide.

## What it misses

- An **existing** local account added to Administrators. There is no `4720` to pair with. A `4732` to
  `S-1-5-32-544` on its own is still worth a look, and dropping the `created_at IS NOT NULL` condition turns this
  into that wider rule.
- A **domain** account added to a server's local Administrators. The `4732` is written, but there is no `4720` on the
  server. Same widening applies.

## When it fires

Disable the account, then check `4624` on the host for its first logon and where that logon came from.
