---
id: DV04
name: Boot integrity weakened (test signing, integrity checks off or kernel debugging on), set by bcdedit or loaded at boot
category: device
status: todo
severity: high
rank: 2
language: esql
index: logs-system.security*, logs-windows.forwarded*, logs-crowdstrike.fdr-*
mitre: [T1553.006, T1542, T1014, T1685]
data_source: Windows Security 4826 (Boot Configuration Data loaded) and CrowdStrike FDR ProcessRollup2 (bcdedit)
suppression:
  fields: [host_key, finding]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Turning on test signing or turning off integrity checks lets Windows load unsigned or self-signed kernel drivers. Rootkits, and EDR killers that bring their own driver, rely on it. Kernel debugging on a production machine is just as wrong. None of these settings belong on a production host.

The rule watches both ends:
- **The command:** `bcdedit /set testsigning on`, `nointegritychecks on`, `debug on`, or a `loadoptions DISABLE_INTEGRITY_CHECKS`. Falcon sees this before the reboot, which is the early warning.
- **The result:** event 4826 is written at every boot and records the boot settings in effect. It catches the change however it was made, including offline edits and tools that write the BCD store directly.

W05 already covers `bcdedit` forcing Safe Mode, and W06 covers recovery being disabled. This rule covers the driver-trust settings neither of them looks at.

## Prerequisite
- 4826 needs **Audit Other Policy Change Events** set to Success. It's in the default audit baseline on many builds. Check with `auditpol /get /subcategory:"Other Policy Change Events"`.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded*, logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.code == "4826"
   OR (event.action == "ProcessRollup2" AND TO_LOWER(process.name) == "bcdedit.exe")
| EVAL msg = TO_LOWER(COALESCE(message, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, "")),
       host_key = TO_LOWER(MV_FIRST(SPLIT(COALESCE(winlog.computer_name, host.name), ".")))
| GROK msg """load options:[ \t]*%{GREEDYDATA:load_options}"""
| GROK msg """kernel debugging:[ \t]*%{WORD:kernel_debug}"""
| GROK msg """test signing:[ \t]*%{WORD:test_signing}"""
| GROK msg """disable integrity checks:[ \t]*%{WORD:integrity_off}"""
| GROK msg """hypervisor debugging:[ \t]*%{WORD:hv_debug}"""
| EVAL finding = CASE(
    event.code == "4826" AND test_signing == "yes", "booted with test signing",
    event.code == "4826" AND (integrity_off == "yes" OR load_options LIKE "*disable_integrity_checks*"), "booted with integrity checks off",
    event.code == "4826" AND (kernel_debug == "yes" OR hv_debug == "yes"), "booted with kernel debugging",
    cmd RLIKE ".*testsigning +(on|yes|true).*", "bcdedit set test signing",
    cmd RLIKE ".*nointegritychecks +(on|yes|true).*" OR cmd LIKE "*disable_integrity_checks*", "bcdedit disabled integrity checks",
    cmd RLIKE ".*debug +(on|yes|true).*" OR cmd LIKE "*/dbgsettings *" OR cmd LIKE "*debugtype*", "bcdedit enabled kernel debugging",
    NULL)
| WHERE finding IS NOT NULL
| KEEP @timestamp, host_key, finding, load_options, test_signing, integrity_off, kernel_debug, hv_debug,
       user.name, process.parent.name, process.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ FileName=/^bcdedit\.exe$/i
| case {
    CommandLine=/testsigning +(on|yes|true)/i
      | finding := "bcdedit set test signing";
    CommandLine=/nointegritychecks +(on|yes|true)|disable_integrity_checks/i
      | finding := "bcdedit disabled integrity checks";
    CommandLine=/debug +(on|yes|true)|\/dbgsettings |debugtype/i
      | finding := "bcdedit enabled kernel debugging";
  }
| table([@timestamp, aid, ComputerName, finding, UserName, ParentBaseFileName, CommandLine])
```
The 4826 branch (booted with test signing, integrity checks off or kernel debugging) isn't in the LogScale version because Windows Security events aren't in Falcon.

**How the parsing works.** 4826 renders each setting as `Name: Yes|No` on its own line. Each `GROK` captures one word after the label. `Load Options` can hold several switches, so it takes the rest of the line (the first match is the general one, which comes before `HyperVisor Load Options`). `Flight Signing` is deliberately ignored, because Windows Insider builds turn it on. The structured `winlog.event_data` copies of these settings stay as raw `%%1842`/`%%1843` codes, which is why the rendered `message` is parsed instead.

The bcdedit patterns need the setting name followed by a value that turns it on. `debug +(on|yes|true)` also covers `bootdebug` and `hypervisordebug`. A looser `*testsigning*on*` would also match `testsigning off` followed by any later "on" (a `.conf` path, for example).

## Suppression
Suppress by `host_key`, `finding` for 24h. Alerts missing a key field are not suppressed. A host booted with test signing logs 4826 on every reboot until it's fixed. Going from "bcdedit set" to "booted with" is a new finding and still alerts.

## Known false positives / exclusions
- **Driver developers and kernel debugging labs.** These are known machines. Exclude them by `host_key`, and keep them off the production domain if you can.
- **Hardware vendor tools** that turn test signing on to load an unsigned driver (some older RAID, fan-control or RGB utilities). Treat each as a finding to remove, not a permanent exclusion.
- **`bcdedit /enum` and `/v`** never match, because the patterns require a setting being turned on.

## Triage
- **bcdedit on a production host:** find the parent process and user. Expect a reboot next, followed by an unsigned driver load. Check CS01 (vulnerable or unsigned driver load) for that host after the reboot.
- **Booted with test signing or integrity checks off:** list the drivers loaded since boot from FDR (`DriverLoad`), and look for unsigned ones or ones from user-writable paths. Treat the host as compromised at kernel level, and reimage rather than clean it.
- **Kernel debugging:** a live kernel debugger means full control of the host. Check for a network debugger target (`debugtype net`).

## Test
On a lab VM, run `bcdedit /set testsigning on` (the FDR branch fires), reboot (4826 shows "Test Signing: Yes"), then `bcdedit /set testsigning off`.
