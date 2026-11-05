---
id: KEYLOG-01
name: Keylogger in script content - a script that references the keyboard-capture APIs (GetAsyncKeyState, low-level keyboard hook, raw input)
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1056.001]
data_source: CrowdStrike FDR ScriptControlScanInfo and ScriptControlDetectInfo (Windows)
suppression:
  fields: [host.name]
  duration: 6h
  missing_fields: do_not_suppress
---
**Catches:** PowerShell and .NET keyloggers by the code itself. Falcon's script-control events carry a script's content when it's written or run, so a keylogger that reaches into the Windows keyboard APIs is visible before it captures a single keystroke. This is the PowerSploit `Get-Keystrokes`, Empire/C2 keylogger-module shape, and hand-rolled P/Invoke loggers.

There are only a few ways to read the keyboard from a script, and ordinary scripts don't use any of them:
- **`GetAsyncKeyState`** - the polling logger, by far the most common. Strong on its own.
- **`SetWindowsHookEx` with the low-level keyboard hook** (`WH_KEYBOARD_LL`, or the hook id `13`) - the callback logger.
- **`RegisterRawInputDevices` for the keyboard usage page** (`0x06`) - the raw-input logger.

The matched call is pulled into `Match`, so the alert shows the keylogging line, not just that something fired. FDR sees the content after decoding, so an obfuscated `Invoke-Expression` of a Base64 blob is matched on the decoded code.

Run every 10 minutes over the last 15.
```logscale
#event_simpleName=/^(ScriptControlScanInfo|ScriptControlDetectInfo)$/ event_platform=Win ScriptContent=/(?<Match>getasynckeystate|setwindowshookex[\s\S]{0,80}wh_keyboard|setwindowshookex\s*\(\s*13|registerrawinputdevices[\s\S]{0,160}0x0*6)/iF
| case {
    ScriptContentSource=1 | ScriptContentSource := "FILE WRITTEN";
    ScriptContentSource=2 | ScriptContentSource := "SCRIPT EXECUTED";
    * ;
  }
| select([@timestamp, #event_simpleName, ComputerName, UserName, ScriptContentSource, ScriptContentName, Match, ScriptContent])
```
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// Script content on Windows (RLIKE can't do this - no case flag, no \s, whole-value only - so GROK runs the regex)
| WHERE event.action IN ("scriptcontrolscaninfo", "scriptcontroldetectinfo") AND data.event_platform == "Win"
| GROK data.ScriptContent """(?i)(?<matched>getasynckeystate|setwindowshookex[\s\S]{0,80}wh_keyboard|setwindowshookex\s*\(\s*13|registerrawinputdevices[\s\S]{0,160}0x0*6)"""
| WHERE matched IS NOT NULL
| EVAL data.ScriptContentSource = CASE(TO_STRING(data.ScriptContentSource) == "1", "FILE WRITTEN",
                                       TO_STRING(data.ScriptContentSource) == "2", "SCRIPT EXECUTED",
                                       TO_STRING(data.ScriptContentSource))
| KEEP @timestamp, event.action, host.name, user.name, data.ScriptContentSource, data.ScriptContentName,
       matched, data.ScriptContent, _id, _index, _version
```
Suppress by host for 6h.

## What it catches and what it doesn't
- **Caught:** any script (PowerShell, a dropped `.ps1`, a C# snippet compiled with `Add-Type`) that references these keyboard APIs - the code is the signal, so obfuscation that Falcon decodes doesn't hide it.
- **Not caught here:** a compiled keylogger (an `.exe` or a C2 in-memory module that never surfaces as script content). Falcon's own Input Capture detections (T1056.001) cover most of those - bring them into the SIEM.
- **Not caught here:** Linux keyloggers. Those read `/dev/input/event*`, run `xinput test`, or attach `strace` to `sshd`/`sudo` - command-line signals, not script content. Worth a separate Linux rule if you want it.
- **Clipboard capture** (T1115) and screen capture are a different API set; this rule is keystrokes only.

## Before turning it on
Confirm your estate collects `ScriptControlScanInfo`/`ScriptControlDetectInfo` on Windows and that `ScriptContent` is populated:
```logscale
#event_simpleName=/^(ScriptControlScanInfo|ScriptControlDetectInfo)$/ event_platform=Win
| groupBy([#event_simpleName], function=[count(ScriptContent, as=with_content), count(as=total)], limit=max)
```
Then run the rule over 30 days. A security-tooling repo, an AutoHotkey build, or an accessibility/remote-input product may legitimately carry these strings - exclude those by host, not by muting a signal.

## When it fires
`Match` is the keylogging call, `ScriptContentName` the file or script, `ScriptContentSource` whether it was written or executed. Read `ScriptContent` for how the captured keys are stored (a file in `%APPDATA%`/`%TEMP%`, the registry) and exfiltrated (an HTTP POST, an SMTP send). Pivot on the host and user, find the process that wrote or ran it (13's web-worker pivot if it came from a web server), and treat captured credentials as compromised - rotate anything typed on that host.
