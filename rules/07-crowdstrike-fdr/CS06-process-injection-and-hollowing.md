---
id: CS06
name: Process injection, hollowing or suspicious remote thread
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1055, T1055.012, T1620]
data_source: CrowdStrike FDR ReflectiveDotnetModuleLoad and DllInjection events
suppression:
  fields: [host.id, src]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Falcon emits dedicated telemetry for in-memory .NET assembly loads and DLL injection. The high-fidelity slice is a .NET assembly loaded from memory into a native Windows process that never hosts .NET (the sacrificial process of `execute-assembly` in Cobalt Strike, Sliver and similar), and a DLL injected from a user-writable path.

In FDR, `InjectedThread`, `ProcessInjection` and `RemoteThreadCreate` carry only process IDs, with no image name or path for either side, so they cannot be filtered here without a join. Falcon's own injection detections reach Elastic through CS04. `SuspiciousCreateThread` and `CreateRemoteThread` are not FDR event names.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE host.os.type == "windows" AND event.action IN ("reflectivedotnetmoduleload", "dllinjection")
// ReflectiveDotnetModuleLoad: data.ImageFileName is the process the assembly was loaded into
// DllInjection: data.InjectedDll is the injected module; process.entity_id is the target, ContextProcessId the source
| EVAL img = TO_LOWER(COALESCE(data.ImageFileName, "")),
       dll = TO_LOWER(COALESCE(data.InjectedDll, "")),
       host_proc = MV_LAST(SPLIT(img, "\\")),
       src = CASE(event.action == "dllinjection", dll, img)
| WHERE (event.action == "reflectivedotnetmoduleload"
         AND host_proc IN ("explorer.exe", "svchost.exe", "rundll32.exe", "regsvr32.exe", "notepad.exe", "werfault.exe", "dllhost.exe", "spoolsv.exe", "gpupdate.exe", "searchprotocolhost.exe", "wuauclt.exe"))
   OR (event.action == "dllinjection"
       AND (dll LIKE """*\\temp\\*""" OR dll LIKE """*\\appdata\\*""" OR dll LIKE """*\\programdata\\*""" OR dll LIKE """*\\users\\public\\*""" OR dll LIKE """*\\downloads\\*"""))
| KEEP @timestamp, host.id, host.name, event.action, src, data.AssemblyName, data.ModuleILPath, process.entity_id, data.ContextProcessId,
       _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ReflectiveDotnetModuleLoad|DllInjection)$/ event_platform=Win
| case {
    #event_simpleName=ReflectiveDotnetModuleLoad
      ImageFileName=/(^|\\)(explorer|svchost|rundll32|regsvr32|notepad|werfault|dllhost|spoolsv|gpupdate|searchprotocolhost|wuauclt)\.exe$/i
      | src := lower(ImageFileName);
    #event_simpleName=DllInjection
      InjectedDll=/\\temp\\|\\appdata\\|\\programdata\\|\\users\\public\\|\\downloads\\/i
      | src := lower(InjectedDll);
  }
| table([@timestamp, aid, ComputerName, #event_simpleName, src, AssemblyName, ModuleILPath, TargetProcessId, ContextProcessId])
```
`msbuild.exe` is not on the list: it compiles inline tasks in memory by design (W04 covers its abuse). PowerShell is not either: `Add-Type` loads assemblies from memory all the time.

## Suppression
Suppress by `host.id`, `src` for 1h. Alerts missing a key field are not suppressed. Injection repeats while the loader runs. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Legitimate software that injects a DLL from a per-user install folder (screen-sharing and accessibility tools under `%APPDATA%`). Baseline and exclude by the exact DLL path.

## Triage
- Find the processes behind the IDs: the target is the ProcessRollup2 with the same `process.entity_id`, the source the one whose `process.entity_id` equals `data.ContextProcessId`. An in-memory assembly in `rundll32.exe` or `notepad.exe` is a post-exploitation framework; check its network callbacks (B06) and the parent that launched the sacrificial process.

## Test
Run the Atomic Red Team T1055 injection tests on a lab host and confirm which of them FDR records as `DllInjection` or `ReflectiveDotnetModuleLoad`.
