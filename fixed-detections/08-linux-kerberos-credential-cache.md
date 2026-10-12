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
| WHERE cmd LIKE "*krb5cc_*" OR cmd LIKE "*.keytab*" OR cmd LIKE "*/var/lib/sss/secrets/*"
     OR cmd LIKE "*/var/lib/sss/db/ccache_*" OR cmd LIKE "*secrets.ldb*" OR cmd LIKE "*.secrets.mkey*"
// file-handling tools: copying, encoding or sending a credential file
| WHERE pname IN ("cp", "mv", "cat", "base64", "xxd", "od", "scp", "rsync", "tar", "zip", "gzip", "dd",
                  "curl", "wget", "nc", "ncat", "socat", "strings", "tdbdump", "ldbsearch", "ldbdump")
     OR STARTS_WITH(pname, "python") OR STARTS_WITH(pname, "perl")
| WHERE NOT parent IN ("sssd", "sssd_be", "sssd_kcm", "adcli", "realm", "certmonger")
| EVAL finding = CASE(
    cmd LIKE "*/var/lib/sss/*" OR cmd LIKE "*secrets.ldb*" OR cmd LIKE "*.secrets.mkey*", "sssd credential store accessed",
    cmd LIKE "*.keytab*", "keytab copied or read",
    "ticket cache copied or read")
| KEEP @timestamp, host.id, host.name, user.name, finding, pname, process.command_line, data.ParentBaseFileName
```
Suppress by `host.id`, `finding` for 6h. Severity high.

- **No fleet, host or person exclusions.** EC2 hosts are in scope.
- **Automation that legitimately handles keytabs** (deployment pipelines distributing a service keytab, for example) should be excluded by its exact parent process or command line, not by user name.
- **If you still want klist visibility,** run it as a weekly hunt, not an alert.

## Before vs after

| | Before | After |
|---|---|---|
| Can fire | Probably not (`threat.technique.name` on a process event) | Yes |
| What it watches | Running `klist` | Copying, encoding or sending ticket caches, keytabs and the SSSD store |
| EC2 Linux fleet | Excluded | Included |
| Person and host exclusions | Yes | None |
| Size | ~60 lines with PID linking | ~20 lines |

## Test
On a lab Linux host, run the Atomic Red Team tests for T1558 that copy a ticket cache, then `cp /etc/krb5.keytab /tmp/` as root. Both should alert. Running `klist` on its own should not.
