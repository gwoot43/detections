---
id: WE10
name: Microsoft Defender detection or Exploit Guard block (malware, high-signal ASR rule, non-browser network protection)
category: windows-events
status: todo
severity: high
language: esql
index: logs-windows.windows_defender-*
mitre: [T1204, T1059, T1003.001, T1055, T1071, T1505.003, T1068]
data_source: Defender Operational channel. 1116/1117 malware detected or acted on, 1006/1015 legacy and behaviour detections, 1121 ASR block, 1126 network protection block.
suppression:
  fields: [host.name, feature, signal]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Defender's operational log is a second opinion beside Falcon. The rule keeps only the parts that are rarely benign:
- **Malware detections** (1116/1117, plus 1006/1015 on older builds), with low-severity PUA and adware dropped.
- **Attack surface reduction (1121)**: blocks for a curated list of ASR rules that almost never fire on normal work (web shell creation, vulnerable driver abuse, Office injecting into other processes, script hosts launching downloaded executables, WMI persistence, Safe Mode reboot). The LSASS rule is noisy because plenty of legitimate software opens LSASS, so that rule alerts only when the process runs from a user-writable path or is a known dump tool.
- **Network protection (1126)** blocks are kept only when the blocked process is **not a browser**. A browser block is a user clicking a bad link, and the email rules already cover that. PowerShell, rundll32 or an Office app connecting to a blocked destination is a payload calling home.

ASR rules and the prevalence-based rules that fire on unknown software (01443614, c1db55ab, d1e49aac with SCCM) are deliberately left out. They need per-estate tuning before they can page anyone.

Defender settings being switched off now lives in **CP06**, and Defender health in **CP05**, so the three rules don't overlap.

## Prerequisite
- In the Elastic **Windows** integration policy, turn on the **Windows Defender** stream. It ships disabled, and without it this rule has no data.
- ASR, network protection and controlled folder access only enforce when Defender AV is in **active** mode. Where Falcon is the registered AV and Defender is in passive mode, only the 1116/1117 branch fires. Check with `Get-MpComputerStatus | Select AMRunningMode`.
- The query only reads `message` and the `winlog.event_data` fields that the integration maps up front. ECS fields such as `process.executable` and `destination.domain` are mapped dynamically when the first event that carries them arrives. Referencing them on a fleet that has never logged a 1121 or 1126 would fail the whole query with "Unknown column".

## Query
```esql
FROM logs-windows.windows_defender-* METADATA _id, _index, _version
| WHERE event.code IN ("1006", "1015", "1116", "1117", "1121", "1126")
| EVAL msg = TO_LOWER(COALESCE(message, "")),
       threat = TO_LOWER(COALESCE(winlog.event_data.Threat_Name, "")),
       sev = TO_LOWER(COALESCE(winlog.event_data.Severity_Name, "")),
       action = TO_LOWER(COALESCE(winlog.event_data.Action_Name, "")),
       detected_path = TO_LOWER(COALESCE(winlog.event_data.Path, ""))
| GROK msg """\bid:\s+%{UUID:asr_rule}"""
| GROK msg """process name:[ \t]*%{GREEDYDATA:proc_raw}"""
| EVAL proc = TRIM(COALESCE(proc_raw, "")),
       feature = CASE(event.code == "1121", "asr",
                      event.code == "1126", "network_protection",
                      "antivirus"),
       asr_name = CASE(
         asr_rule == "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "credential theft from lsass",
         asr_rule == "a8f5898e-1dc8-49a9-9878-85004b8a61e6", "web shell creation on server",
         asr_rule == "56a863a9-875e-4185-98a7-b882c64b5ce5", "exploited vulnerable signed driver",
         asr_rule == "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "office injecting into other processes",
         asr_rule == "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "office creating child process",
         asr_rule == "3b576869-a4ec-4529-8536-b80a7769e899", "office creating executable content",
         asr_rule == "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "win32 api calls from office macro",
         asr_rule == "d3e037e1-3eb8-44c8-a917-57927947596d", "js or vbs launching downloaded executable",
         asr_rule == "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "executable content from email",
         asr_rule == "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "adobe reader creating child process",
         asr_rule == "e6db77e5-3df2-4cf1-b95a-636979351e5b", "persistence through wmi event subscription",
         asr_rule == "33ddedf1-c6e0-47cb-833e-de6133960387", "reboot into safe mode",
         asr_rule == "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "copied or impersonated system tool",
         NULL),
       user_writable = proc LIKE """*\\users\\*""" OR proc LIKE """*\\programdata\\*"""
         OR proc LIKE """*\\windows\\temp\\*""" OR proc LIKE """*\\perflogs\\*""" OR proc LIKE """*\\$recycle.bin\\*""",
       proc_name = MV_LAST(SPLIT(proc, "\\"))
| WHERE (feature == "antivirus" AND sev != "low" AND threat != "" AND NOT threat LIKE "*eicar*")
   OR (feature == "asr" AND asr_name IS NOT NULL
       AND (asr_rule != "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
            OR user_writable
            OR proc_name IN ("rundll32.exe", "powershell.exe", "pwsh.exe", "procdump.exe", "procdump64.exe",
                             "sqldumper.exe", "createdump.exe", "dotnet-dump.exe", "mshta.exe", "wscript.exe", "cscript.exe")))
   OR (feature == "network_protection" AND proc_name != ""
       AND NOT proc_name IN ("msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe",
                             "msedgewebview2.exe", "searchapp.exe", "searchhost.exe"))
| EVAL signal = CASE(feature == "antivirus", threat, feature == "asr", asr_name, proc_name)
| KEEP @timestamp, host.name, winlog.event_data.Detection_User, event.code, feature, signal, threat, sev, action,
       asr_rule, asr_name, proc, detected_path, message, _id, _version, _index
```

**How the parsing works.** `GROK` pulls the ASR rule GUID (`ID: <guid>`) and the `Process Name:` line out of the rendered message. GROK patterns match anywhere in the text, and `GREEDYDATA` stops at the end of the line, so each capture is that one value. The `{`-wrapped detection GUID in 1116 events doesn't match `UUID`, so `asr_rule` is only populated on 1121.

**Adding an ASR rule.** Put its GUID in the `asr_name` CASE. Leave out any rule that blocks unknown software on reputation alone until you have tuned it in audit mode.

## Suppression
Suppress by `host.name`, `feature`, `signal` for 24h. Alerts missing a key field are not suppressed. Defender re-detects the same file on every scan, and an ASR block repeats each time the user retries the document. A new threat name, ASR rule or blocked process on the same host still alerts.

## Known false positives / exclusions
- **Malware branch:** detections on archived mail or quarantined samples in a malware-analysis share. Exclude those hosts or paths.
- **ASR Office child process:** legacy macro-driven line-of-business workbooks. Fix with a per-file ASR exclusion in Defender, not here, so the block and the alert go away together.
- **ASR LSASS:** backup and monitoring agents installed under `ProgramData`. Add the exact `proc` to the WHERE.
- **Network protection:** updaters for third-party software that reach a newly flagged CDN. Confirm the destination with the Defender portal before excluding.

## Triage
- **Malware:** confirm whether Falcon also saw it (CS04), pull the process tree from FDR, and check for the wider chain (W02, W03, W04).
- **ASR block:** the attack was stopped, but the step before it wasn't. Find out how the document or script arrived (E-rules, browser download) and whether a sibling technique succeeded. An LSASS block from a user-writable path means someone tried to dump credentials. Treat it like W01.
- **Network protection, non-browser:** the process was trying to reach known-bad infrastructure. Pull its parent, command line and the destination from `message`, then hunt that destination across Zscaler (N07) and FDR DNS.

## Test
- Malware: drop a non-EICAR test sample from the Microsoft Defender test page, or temporarily remove the `eicar` filter and use EICAR.
- ASR: Microsoft's ASR test documents (Defender demo site) trigger the Office child-process and script rules in block mode.
- Network protection: from PowerShell, `Invoke-WebRequest https://smartscreentestratings2.net` returns a block and a 1126.
