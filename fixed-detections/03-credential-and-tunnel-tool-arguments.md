# 03 · Suspicious credential or tunneling tool arguments → LSASS / SAM credential dumping (Falcon)

**Verdict before:** weak. It excludes the account most post-exploitation runs as, matches mimikatz only in its rarest form, and mixes two unrelated behaviours in one alert.
**After:** a credential-dumping rule built on the command lines that dumping actually needs. The tunneling half (plink `-R`) moves to rule 01 After B, which also covers `ssh -R/-D`, chisel and renamed tunnel agents.

## Before
```kql
event.action:processrollup2 AND (process.command_line.text:*sekurlsa* OR (process.command_line:*\-R\ * AND process.command_line:*\-pw\ *)) AND (NOT user.name:*$)
```

## What's wrong

| # | Problem | Effect |
|---|---|---|
| 1 | `NOT user.name:*$`. Falcon generally records SYSTEM processes under the machine account (`HOST$`); check this in your data. | Everything run as SYSTEM (PsExec, services, scheduled tasks), which is how credential theft usually runs after lateral movement, is excluded. |
| 2 | `sekurlsa` only appears in the command line for one-liners (`mimikatz.exe "sekurlsa::logonpasswords" exit`). Run interactively, the command line is just the binary name. Falcon also blocks known mimikatz builds on its own. | Catches the least likely form of the attack. |
| 3 | Dumping without mimikatz isn't covered: `rundll32 comsvcs.dll MiniDump`, `procdump -ma lsass`, `reg save HKLM\SAM`. | The common living-off-the-land techniques are missed. |
| 4 | The plink branch needs both `-R` and `-pw`. | Misses key-based auth (`-i`), SOCKS (`-D`), Windows' built-in `ssh.exe`, chisel and ligolo. |
| 5 | `process.command_line` is a keyword field. If its mapping has `ignore_above` (often 1024), long command lines aren't indexed and the wildcard can't match them. | Long or encoded command lines slip through. |
| 6 | Credential theft and tunneling in one rule. | One alert name, two different playbooks and ATT&CK techniques. |

## After
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2"
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")),
       pname = MV_LAST(SPLIT(TO_LOWER(COALESCE(process.executable, "")), "\\"))
| EVAL finding = CASE(
    cmd LIKE "*sekurlsa::*" OR cmd LIKE "*lsadump::*" OR cmd LIKE "*kerberos::*", "mimikatz one-liner",
    pname == "rundll32.exe" AND cmd LIKE "*comsvcs*"
      AND (cmd LIKE "*minidump*" OR cmd LIKE "*#24*" OR cmd LIKE "*#+24*" OR cmd LIKE "*#00024*"), "lsass dump via comsvcs",
    cmd LIKE "*lsass*" AND (cmd LIKE "* -ma *" OR cmd LIKE "* -mm *" OR cmd LIKE "*minidump*" OR cmd LIKE "*.dmp*"),
      "lsass memory dump (procdump or similar)",
    pname == "reg.exe" AND (cmd LIKE "* save *" OR cmd LIKE "* export *")
      AND (cmd LIKE """*hklm\\sam*""" OR cmd LIKE """*hklm\\security*""" OR cmd LIKE """*hkey_local_machine\\sam*"""
           OR cmd LIKE """*hkey_local_machine\\security*"""), "sam / security hive saved",
    NULL)
| WHERE finding IS NOT NULL
| KEEP @timestamp, host.id, host.name, user.name, finding, process.executable, process.command_line,
       data.ParentBaseFileName, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| cmd := lower(CommandLine)
| regex("(?<pname>[^\\\\]*)$", field=ImageFileName, strict=false)
| pname := lower(pname)
| case {
    cmd=/sekurlsa::|lsadump::|kerberos::/
      | finding := "mimikatz one-liner";
    pname="rundll32.exe" cmd=/comsvcs/ cmd=/minidump|#24|#\+24|#00024/
      | finding := "lsass dump via comsvcs";
    cmd=/lsass/ cmd=/ -ma | -mm |minidump|\.dmp/
      | finding := "lsass memory dump (procdump or similar)";
    pname="reg.exe" cmd=/ save | export / cmd=/hklm\\sam|hklm\\security|hkey_local_machine\\sam|hkey_local_machine\\security/
      | finding := "sam / security hive saved";
  }
| table([@timestamp, aid, ComputerName, UserName, finding, ImageFileName, CommandLine, ParentBaseFileName])
```
Suppress by `host.id`, `finding` for 1h. Severity critical.

- **No user filter.** SYSTEM context is where this matters most.
- **Ordinal tricks.** comsvcs is often called by ordinal (`#24`, `#+24`, `#00024`) to dodge "MiniDump" string matches, so all three forms are listed.
- **`reg save HKLM\SYSTEM` is left out on purpose.** On its own it's used by backup and imaging tools; SAM and SECURITY are not.
- **This is a command-line complement to Falcon's own credential-theft detections.** Those see the LSASS memory read itself and should stay routed as alerts (library rule CS04).

## Before vs after

| | Before | After |
|---|---|---|
| SYSTEM-context activity | Excluded | Included |
| mimikatz | One-liner only | One-liner (Falcon native covers the rest) |
| comsvcs MiniDump, procdump, SAM hive save | Missed | Caught |
| Tunneling | plink `-R` with `-pw` only | Moved to rule 01 After B (ssh/plink `-R`/`-D`, chisel, cloudflared, ngrok, dev tunnels) |
| Alert meaning | Two behaviours mixed | One behaviour, one playbook |

## Test
On a lab host, run the Atomic Red Team tests for T1003.001 (comsvcs and procdump variants) and T1003.002 (registry hive save). Falcon will likely block the dump, but the process event still arrives and the rule should fire.
