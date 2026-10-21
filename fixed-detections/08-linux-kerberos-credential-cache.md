# 08 · Linux Kerberos credential cache enumeration → ticket cache and keytab theft (Linux)

**Verdict before:** almost certainly never fires, excludes the whole cloud Linux fleet, and watches a benign command.
**After:** a short rule for what matters: another process copying, encoding or sending a Kerberos ticket cache, a keytab, or SSSD's credential store.

## Before
```text
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.dataset == "crowdstrike.data" AND event.action == "processrollup2"
  AND ( process.executable == "/usr/bin/klist" OR process.command_line IN ( <4 exact wrapper command lines> ) )
| WHERE host.name NOT LIKE "*ap-southeast-2.compute.internal"
| EVAL cmd = TO_LOWER(process.command_line), exe = TO_LOWER(process.executable), parent_name = TO_LOWER(data.ParentBaseFileName)
| EVAL is_klist = event.action == "processrollup2" AND STARTS_WITH(cmd, "klist") AND cmd != "klist purge"
          AND user.name IS NOT NULL AND NOT user.name IN ("excluded_user_1", "automation_account")
          AND host.name != "excluded-host-1" AND exe == "/usr/bin/klist"
          AND threat.technique.name == "Steal or Forge Kerberos Tickets",
       is_authorised_parent = event.action == "processrollup2" AND cmd IN ( <same 4 command lines, lowercased> )
          AND exe == "/usr/bin/bash" AND parent_name IN ("python2.7", "python3.9", "platform-python3.6", "python3.12")
| WHERE is_klist OR is_authorised_parent
| WHERE COALESCE(event.ingested, @timestamp) <= NOW() - 5 minutes
| EVAL link_pid = CASE( is_klist, COALESCE(data.ParentProcessId, event.id), is_authorised_parent, data.TargetProcessId )
| ... marker EVALs ...
| STATS klist_count = SUM(klist_marker), authorised_parent_count = SUM(authorised_parent_marker), ... BY host.id, host.name, link_pid
| WHERE klist_count > 0 AND authorised_parent_count == 0 AND klist_time >= NOW() - 45 minutes
| KEEP ... | SORT klist_time ASC
```
(Shortened; the exact wrapper command lines and marker columns don't change the analysis.)

## What's wrong

| # | Problem | Effect |
|---|---|---|
| 1 | `is_klist` requires `threat.technique.name == "Steal or Forge Kerberos Tickets"` on a plain process event. That field is normally only set on detections, not raw `processrollup2` events. Check one event in Discover. | If the field is empty, `is_klist` is never true and **the rule never fires**. |
| 2 | `STARTS_WITH(cmd, "klist")`. A run as `/usr/bin/klist …` starts with `/usr`. | Full-path runs are missed even if #1 holds. |
| 3 | `host.name NOT LIKE "*ap-southeast-2.compute.internal"`. | The entire EC2 Linux fleet is excluded. A `NOT LIKE` on a missing `host.name` also drops the row. |
| 4 | A named person and a named host excluded inline. | Permanent blind spots on exactly the accounts an attacker would most like to use. |
| 5 | `COALESCE(data.ParentProcessId, event.id)`. An event ID is not a process ID. | The fallback can never link to a parent; harmless but confusing. |
| 6 | Watches `klist`, which admins, sssd and automation run all day. Stealing tickets doesn't need klist: the attacker copies the ticket cache or keytab file, or reads SSSD's credential store. | Even when it works, it watches the wrong step. |
| 7 | ~60 lines of parent-PID linking to suppress one automation wrapper. | Hard to maintain, and fragile when the wrapper changes. |

## After
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2"
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")),
       pname = MV_LAST(SPLIT(TO_LOWER(COALESCE(process.executable, "")), "/")),
       parent = TO_LOWER(COALESCE(data.ParentBaseFileName, ""))
| WHERE cmd RLIKE """.*(krb5cc_|\.keytab|/var/lib/sss/secrets/|/var/lib/sss/db/ccache_|secrets\.ldb|\.secrets\.mkey).*"""
  AND NOT pname IN ("kinit", "klist", "kdestroy", "kvno", "kswitch", "ktutil", "adcli", "realm", "msktutil", "net",
                    "winbindd", "sssd", "sssd_be", "sssd_kcm", "gssproxy", "certmonger", "sss_cache", "sssctl")
  AND NOT parent IN ("sssd", "sssd_be", "sssd_kcm", "adcli", "realm", "certmonger")
| KEEP @timestamp, host.id, host.name, user.name, pname, process.command_line, data.ParentBaseFileName, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| CommandLine=/krb5cc_|\.keytab|\/var\/lib\/sss\/secrets\/|\/var\/lib\/sss\/db\/ccache_|secrets\.ldb|\.secrets\.mkey/i
| regex("(?<pname>[^/]*)$", field=ImageFileName, strict=false)
| pname := lower(pname)
| !in(field="pname", values=["kinit", "klist", "kdestroy", "kvno", "kswitch", "ktutil", "adcli", "realm", "msktutil", "net",
                            "winbindd", "sssd", "sssd_be", "sssd_kcm", "gssproxy", "certmonger", "sss_cache", "sssctl"])
| !in(field="ParentBaseFileName", ignoreCase=true, values=["sssd", "sssd_be", "sssd_kcm", "adcli", "realm", "certmonger"])
| table([@timestamp, aid, ComputerName, UserName, pname, CommandLine, ParentBaseFileName])
```
Suppress by `host.id`, `pname` for 6h.

- **Allowlist, not denylist.** Any process referencing these files alerts unless it's known Kerberos or SSSD tooling.
- **Null-safe.** `COALESCE` on the command line and executable, so an event with an empty field isn't silently dropped by the `NOT ... IN` checks.
- **SSSD paths narrowed** to `secrets/` and `db/ccache_*`. The broader `/var/lib/sss/` also matched `pipes/`, `mc/` and `pubconf/`.
- **No fleet, host or person exclusions.** EC2 hosts are in scope.

### Build the allowlist before enabling
Run this over the last 30 days. Anything with steady volume across many hosts (a Java or Kafka service started with `--keytab`, deployment tooling) is a candidate for the `pname` list, or for an exact command-line exclusion if it's a script. Anything rare is what the rule should alert on.
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "processrollup2"
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE cmd RLIKE """.*(krb5cc_|\.keytab|/var/lib/sss/secrets/|/var/lib/sss/db/ccache_|secrets\.ldb|\.secrets\.mkey).*"""
| STATS runs = COUNT(*), hosts = COUNT_DISTINCT(host.id), examples = VALUES(process.command_line)
    BY process.executable, data.ParentBaseFileName
| SORT runs DESC
```

**CrowdStrike (Falcon LogScale / Advanced Event Search), run over the last 30 days**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| CommandLine=/krb5cc_|\.keytab|\/var\/lib\/sss\/secrets\/|\/var\/lib\/sss\/db\/ccache_|secrets\.ldb|\.secrets\.mkey/i
| default(field=ImageFileName, value="unknown", replaceEmpty=true)
| default(field=ParentBaseFileName, value="unknown", replaceEmpty=true)
| groupBy([ImageFileName, ParentBaseFileName], function=[count(as=runs), count(aid, distinct=true, as=hosts),
                                                       collect([CommandLine])], limit=max)
| sort(runs, order=desc, limit=1000)
```

## Before vs after

| | Before | After |
|---|---|---|
| Can fire | Probably not (`threat.technique.name` on a process event) | Yes |
| What it watches | Running `klist` | Any process touching ticket caches, keytabs or the SSSD store, except known Kerberos tooling |
| EC2 Linux fleet | Excluded | Included |
| Person and host exclusions | Yes | None |
| Size | ~60 lines with PID linking | ~12 lines |

## Test
On a lab Linux host, run the Atomic Red Team tests for T1558 that copy a ticket cache, then `cp /etc/krb5.keytab /tmp/` as root. Both should alert. Running `klist` on its own should not.
