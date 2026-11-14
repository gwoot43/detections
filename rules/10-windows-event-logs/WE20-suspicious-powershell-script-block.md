---
id: WE20
name: Suspicious PowerShell script block - AMSI or ETW bypass, reflective load, decode-and-execute or download cradle (4104)
category: windows-event-logs
status: todo
language: esql
index: logs-windows.powershell_operational-*
mitre: [T1059.001, T1562.001, T1620, T1027]
data_source: Windows PowerShell Operational 4104 (script block logging)
suppression:
  fields: [host.name, user.name]
  duration: 6h
  missing_fields: do_not_suppress
---

Script block logging records the text PowerShell actually runs, **after** decoding. So `-EncodedCommand` is not the
signal here: that belongs to the process command line (`W04`). What the script block shows is the decoded behaviour.

That makes a few strings very precise:

- **AMSI bypass:** touching `AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer` or `amsiContext`. No administrative script
  tampers with the Antimalware Scan Interface. **Alert grade.**
- **ETW patch:** `EtwEventWrite` in a script is an attempt to blind event tracing. **Alert grade.**
- **Known credential tooling:** `Invoke-Mimikatz`. **Alert grade.**
- **Reflective load:** `[System.Reflection.Assembly]::Load(`, the way in-memory .NET tooling is run. **Risk grade.**
- **Decode-and-execute:** `FromBase64String(` followed closely by `IEX` / `Invoke-Expression`. **Risk grade.**
- **Download cradle:** `Net.WebClient` with `DownloadString` / `DownloadData`, or `IEX (New-Object Net.WebClient)`.
  **Risk grade**, because installers such as Chocolatey's bootstrap use exactly this.

The `tier` column carries the Alert/Risk split, so one rule feeds both the alert queue and the risk score.

## Query

Run every 5 minutes with a 10-minute lookback.

```esql
FROM logs-windows.powershell_operational-* METADATA _id, _index, _version
| WHERE event.code == "4104"
| GROK powershell.file.script_block_text """(?i)(?<matched>amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext|etweventwrite|invoke-mimikatz|reflection\.assembly\]::load\s{0,8}\(|frombase64string\s{0,8}\(.{0,160}(iex|invoke-expression)|(iex|invoke-expression)\s{0,8}\(?\s{0,8}\(?\s{0,8}new-object\s{1,8}(system\.)?net\.webclient|net\.webclient\)?\s{0,8}\.\s{0,8}download(string|data)\s{0,8}\()"""
| WHERE matched IS NOT NULL
| EVAL m = TO_LOWER(matched),
       finding = CASE(m LIKE "amsi*", "amsi_bypass",
                      m LIKE "etw*", "etw_patch",
                      m LIKE "invoke-mimikatz*", "credential_tool",
                      m LIKE "reflection*", "reflective_load",
                      m LIKE "frombase64*", "decode_and_execute",
                      "download_cradle"),
       tier = CASE(finding IN ("amsi_bypass", "etw_patch", "credential_tool"), "alert", "risk")
| KEEP @timestamp, host.name, user.name, tier, finding, matched, powershell.file.script_block_id,
       powershell.file.script_block_text, file.path, _id, _version, _index
```

## Before turning it on

- **Script block logging must be on.** It is the "Turn on PowerShell Script Block Logging" policy. Without it, `4104`
  is written only for blocks PowerShell itself flags as suspicious. Probe it:

```esql
FROM logs-windows.powershell_operational-*
| WHERE @timestamp >= NOW() - 24 hours AND event.code == "4104"
| STATS blocks = COUNT(*), hosts = COUNT_DISTINCT(host.name)
```

  If `hosts` is far below your Windows fleet size, the policy is not deployed broadly and the gaps are the coverage.
- **The risk-tier population.** Run the query over 30 days and look at what lands in `download_cradle` and
  `reflective_load`. Expect package bootstrappers, vendor agents and admin tooling. Exclude each as a pair of the
  script path (`file.path`) and the host group that runs it, never by host alone.

## What it misses

- Obfuscation that splits the strings, such as `'Am'+'siUtils'` or character-code arrays. PowerShell logs a
  deobfuscated block only where the engine resolves it. Concatenated names usually still appear in a later block,
  but not always.
- PowerShell v2, which writes no `4104` at all. A `powershell -version 2` downgrade is its own signal on the process
  command line.
- Unmanaged PowerShell hosted inside another process. Script block logging still fires there, but `host.name` is the
  only context. Pivot to the Falcon process events for the host process.

## When it fires

A single script is often split across several `4104` events. Pull the whole script by `script_block_id`:

```esql
FROM logs-windows.powershell_operational-*
| WHERE event.code == "4104" AND powershell.file.script_block_id == "<script_block_id>"
| SORT powershell.sequence ASC
| KEEP @timestamp, powershell.sequence, powershell.total, powershell.file.script_block_text
```
