---
id: WE09
name: NTDS.dit and shadow-copy access on a domain controller
category: windows-event-logs
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*, logs-system.security*, logs-windows.forwarded*
mitre: [T1003.003]
data_source: CrowdStrike FDR ProcessRollup2 (DCs) and Windows Security 4656/4663 on NTDS
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
`ntds.dit` holds every password hash in the domain. It is copied by making a volume shadow copy and reading the file out, or with `ntdsutil ifm`, `esentutl`, `diskshadow`, or a straight `reg save` of the hives. Backup software does some of this on a schedule; nothing else does.

`rules/10-windows-event-logs/WE09` has the right command set. The two changes here: **the DC check is an entity list instead of a hostname pattern** (`dc*` / `*-dc*` is guesswork that a renamed server defeats and a `dc-laptop` trips), and the **`reg save` of SAM/SECURITY** is folded in as its own labelled shape rather than an `OR` term, because the hive trio can be pulled off any member server too.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// 15 minutes in the query: a shadow copy and the copy-out are minutes apart at most.
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.action IN ("processrollup2", "syntheticprocessrollup2")
| EVAL pname = TO_LOWER(COALESCE(process.name, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, "")),
// The DCs, as a list. Backups and DC rebuilds legitimately run these commands; member servers running them
// are the same act on a smaller database, which is why the host list is a scope and not the detection.
       on_dc = host.name IN ("<dc01>", "<dc02>", "<dc03>")
| EVAL dit_read = (pname == "ntdsutil.exe" AND (cmd LIKE "*ifm*" OR cmd LIKE "*create full*" OR cmd LIKE "*ac i ntds*"))
                 OR (pname == "vssadmin.exe" AND cmd LIKE "*create shadow*")
                 OR (pname == "diskshadow.exe" AND (cmd LIKE "*create*" OR cmd LIKE "*expose*" OR cmd LIKE "*/s *"))
                 OR (pname == "esentutl.exe" AND cmd LIKE "*ntds*"),
// Copying out of a mounted shadow copy, and the hive trio, are the second half of the same theft.
       copy_out = cmd LIKE "*/harddiskvolumeshadowcopy*" OR cmd LIKE "*ntds.dit*",
       hive_save = pname == "reg.exe" AND cmd LIKE "*save*"
                   AND (cmd LIKE """*hklm\\sam*""" OR cmd LIKE """*hklm\\security*""" OR cmd LIKE """*hklm\\system*""")
| WHERE (dit_read OR copy_out OR hive_save) AND (on_dc OR hive_save)
| EVAL shape = CASE(dit_read, "database_theft", hive_save, "hive_save", "shadow_copy_read")
| STATS events = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        commands = MV_SLICE(VALUES(process.command_line), 0, 4),
        parents = MV_SLICE(VALUES(process.parent.name), 0, 3),
        users = MV_SLICE(VALUES(user.name), 0, 3)
    BY host.name, shape, pname
| SORT events DESC
| LIMIT 100
```

Deploy every 5 minutes over the last 15. Suppress by `host.name` + `shape` for 24h.

## Reading the alert
- **`shape`** names the theft: `database_theft` is the AD database or its filesystem copy, `hive_save` is SAM/SECURITY/SYSTEM (local accounts and LSA secrets — enough to pivot, not enough for domain-wide hashes), `shadow_copy_read` is the copy-out that follows a shadow creation.
- **`parents`** is the discriminator on a DC: `services.exe` is backup software, `explorer.exe` is a human at a console, `cmd.exe`/`powershell.exe` under an RMM agent is the attack. A DC has no interactive users; treat any `explorer.exe` parent as a red flag.
- **`users`** on a DC should be `SYSTEM` or a documented backup account. A domain admin's own account running `ntdsutil` at 02:00 is a question for them.
- **`events`** above one with different `commands` in one host row is a repeated attempt, not a retry.

## Nearest benign twins
- **Backup software** (Veeam, Commvault, Windows Server Backup) creating shadow copies and reading the database. Signed binaries, `services.exe` parent, fixed command lines, and a nightly cadence — entity pairs, and the reason `parents` matters more than the command.
- **DC promotion and rebuild**, which runs `ntdsutil` legitimately. Planned, on the new host, and the actor is the build account.
- **A manual restore test** by the infrastructure team. Ticketed; the tell is that it happens once and the analyst can name the engineer.

## What it misses
- **Reading `ntds.dit` through an already-existing shadow copy** without creating one: a file read, not a command, so it needs 4663 with SACL auditing on the file.
- **DCSync**, which reads the same secrets over the network without touching the file — `I01` / `dcsync-with-origin`.
- **`vssadmin delete shadows`** after the fact, which is anti-forensics rather than theft and belongs with the log-clearing rules.
- **A DC with no Falcon sensor**, where none of this is visible. That is the same gap the VAPOR PANDA reporting notes the actors inventory for.

## Probe before enabling
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 7 days
| STATS events = COUNT(*) BY host.name, host.os.type
| WHERE host.name IN ("<dc01>", "<dc02>", "<dc03>")
| SORT events DESC
```
Fill the entity list from this, not from a naming convention. If any DC returns nothing, it is not reporting process events and the rule silently does not cover it.

## References
- `rules/10-windows-event-logs/WE09-ntds-and-shadow-access.md` - the rule this refines
- `rules/05-identity/I01-dcsync.md` - the network route to the same secrets
- MITRE T1003.003 (NTDS), T1003.002 (SAM), T1490-adjacent shadow-copy abuse
