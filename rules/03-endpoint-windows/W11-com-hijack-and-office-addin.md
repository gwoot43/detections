---
id: W11
name: COM hijack or Office add-in persistence
category: endpoint-windows
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1546.015, T1137.006]
data_source: CrowdStrike FDR registry and file events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Two persistence methods that survive reboot and run inside trusted processes. A per-user COM class (HKCU CLSID InprocServer32) pointing at a DLL in a user-writable path overrides a system COM object so the attacker's DLL loads when that object is called. A DLL or template dropped into an Office startup or add-in path loads every time Office starts.

FDR writes registry keys as `\REGISTRY\USER\<SID>...` (in `registry.path`), not `HKEY_USERS`. OneDrive and the Teams meeting add-in register per-user COM servers under `%LOCALAPPDATA%` on every update, so those two folders are excluded. Word saving its own `Normal.dotm` and Excel saving its own `PERSONAL.XLSB` are routine and also excluded. The file branch only counts file writes.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE host.os.type == "windows"
| EVAL k = TO_LOWER(TO_STRING(COALESCE(registry.path, registry.key, ""))),
       v = TO_LOWER(TO_STRING(COALESCE(registry.data.strings, registry.value, ""))),
       f = TO_LOWER(TO_STRING(COALESCE(file.path, ""))),
       pname = TO_LOWER(COALESCE(process.name, ""))
| WHERE
     (event.action IN ("asepvalueupdate", "reggenericvalueupdate", "registryoperationdetectinfo")
      AND k LIKE """\\registry\\user\\*""" AND k LIKE """*\\clsid\\*inprocserver32*"""
      AND (v LIKE """*\\appdata\\*""" OR v LIKE """*\\temp\\*""" OR v LIKE """*\\programdata\\*""" OR v LIKE """*\\users\\public\\*""")
      AND NOT (v LIKE """*\\appdata\\local\\microsoft\\onedrive\\*""" OR v LIKE """*\\appdata\\local\\microsoft\\teamsmeetingadd*"""))
  OR (event.action LIKE "*written"
      AND (f LIKE """*\\microsoft\\word\\startup\\*""" OR f LIKE """*\\microsoft\\excel\\xlstart\\*"""
           OR f LIKE """*\\microsoft\\addins\\*""" OR f LIKE """*\\microsoft\\templates\\normal.dotm""")
      AND NOT (pname == "winword.exe" AND f LIKE "*normal.dotm")
      AND NOT (pname == "excel.exe" AND f LIKE "*personal.xlsb"))
| KEEP @timestamp, host.id, host.name, user.name, event.action, k, v, f, process.name, process.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(AsepValueUpdate|RegGenericValueUpdate|RegistryOperationDetectInfo|.*Written)$/ event_platform=Win
| v := coalesce([RegStringValue, RegValueName])
| case {
    #event_simpleName=/^(AsepValueUpdate|RegGenericValueUpdate|RegistryOperationDetectInfo)$/
      RegObjectName=/^\\registry\\user\\/i RegObjectName=/\\clsid\\.*inprocserver32/i
      v=/\\appdata\\|\\temp\\|\\programdata\\|\\users\\public\\/i
      | NOT v=/\\appdata\\local\\microsoft\\onedrive\\|\\appdata\\local\\microsoft\\teamsmeetingadd/i;
    #event_simpleName=/Written$/
      TargetFileName=/\\microsoft\\word\\startup\\|\\microsoft\\excel\\xlstart\\|\\microsoft\\addins\\|\\microsoft\\templates\\normal\.dotm$/i
      | NOT (ContextBaseFileName=/^winword\.exe$/i AND TargetFileName=/normal\.dotm$/i)
      | NOT (ContextBaseFileName=/^excel\.exe$/i AND TargetFileName=/personal\.xlsb$/i);
  }
| select([@timestamp, aid, ComputerName, UserName, #event_simpleName, RegObjectName, RegValueName, RegStringValue, TargetFileName,
         ContextBaseFileName, CommandLine])
```

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Installers touch these paths repeatedly in one session; a different host still alerts. Registry events carry no user, so the user is not a key. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Legitimate Office add-in installers and COM-based software. Baseline for two weeks and exclude by the writing process (`process.name` on file writes) or the specific add-in path.
- Users installing an Excel add-in (`.xlam`) into `AddIns` themselves. Confirm with the user.

## Triage
- Identify the DLL or template, check whether it is signed and where it came from, and remove the registry value or file. Look for the same artefact on other hosts.

## Test
Write an HKCU CLSID InprocServer32 value pointing at a DLL in %APPDATA% on a lab host, or drop a benign template into the Word startup folder.
