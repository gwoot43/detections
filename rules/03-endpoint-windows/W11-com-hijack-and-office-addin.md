---
id: W11
name: COM hijack or Office add-in persistence
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1546.015, T1137.006]
data_source: CrowdStrike FDR registry and file events
suppression:
  fields: [host.name, user.name]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Two persistence methods that survive reboot and run inside trusted processes. A per-user COM class (HKCU CLSID InprocServer32) pointing at a DLL in a user-writable path overrides a system COM object so the attacker's DLL loads when that object is called. A DLL or template dropped into an Office startup or add-in path loads every time Office starts.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE host.os.type == "windows"
| EVAL k = TO_LOWER(TO_STRING(COALESCE(registry.path, registry.key, ""))),
       v = TO_LOWER(TO_STRING(COALESCE(registry.data.strings, registry.value, ""))),
       f = TO_LOWER(TO_STRING(COALESCE(file.path, "")))
| WHERE
     (event.action IN ("AsepValueUpdate", "RegGenericValueUpdate", "RegistryOperationDetectInfo")
      AND k LIKE "*\\clsid\\*inprocserver32*" AND k LIKE "hkey_users*"
      AND (v LIKE "*\\appdata\\*" OR v LIKE "*\\temp\\*" OR v LIKE "*\\programdata\\*" OR v LIKE "*\\users\\public\\*"))
  OR (f LIKE "*\\microsoft\\word\\startup\\*" OR f LIKE "*\\microsoft\\excel\\xlstart\\*"
      OR f LIKE "*\\microsoft\\addins\\*" OR f LIKE "*\\word\\startup\\*"
      OR f LIKE "*\\template\\normal.dotm" OR f LIKE "*\\microsoft\\templates\\normal.dotm")
| KEEP @timestamp, host.name, user.name, event.action, k, v, f, process.name, process.command_line
```

## Suppression
Suppress by `host.name`, `user.name` for 24h. Alerts missing a key field are not suppressed. Installers touch these paths repeatedly in one session; a different host or user still alerts.

## Known false positives / exclusions
- Legitimate Office add-in installers and COM-based software. Baseline for two weeks and exclude by the signed writing process or the specific add-in path.

## Triage
- Identify the DLL or template, check whether it is signed and where it came from, and remove the registry value or file. Look for the same artefact on other hosts.

## Test
Write an HKCU CLSID InprocServer32 value pointing at a DLL in %APPDATA% on a lab host, or drop a benign template into the Word startup folder.
