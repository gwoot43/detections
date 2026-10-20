---
id: CS01
name: Vulnerable or unsigned driver loaded (BYOVD)
category: crowdstrike-fdr
status: todo
severity: critical
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1068, T1211, T1685]
data_source: CrowdStrike FDR DriverLoad events
suppression:
  fields: [host.id, img]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
BYOVD is the dominant EDR-killer delivery method in 2026 (Reynolds, RansomHub, Akira, Scattered Spider). The kernel-side signal is a known-vulnerable signed driver, or any driver, loading from a user-writable path. FDR's driver-load telemetry sees this even when the process side was obfuscated. Maintain the vulnerable-driver hash list from loldrivers.io and your intel feed.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "driverload" AND host.os.type == "windows"
// the integration writes the driver to dll.path / dll.hash.sha256 on DriverLoad, not file.* or process.*
| EVAL img = TO_LOWER(COALESCE(dll.path, "")),
       h = TO_LOWER(COALESCE(dll.hash.sha256, ""))
| WHERE
     // driver from a user-writable path is almost always BYOVD; Defender platform updates load drivers from ProgramData
     ((img LIKE """*\\temp\\*""" OR img LIKE """*\\users\\*""" OR img LIKE """*\\programdata\\*""" OR img LIKE """*\\appdata\\*""" OR img LIKE """*\\downloads\\*""" OR img LIKE """*\\perflogs\\*""")
      AND NOT img LIKE """*\\programdata\\microsoft\\windows defender\\platform\\*""")
     // known vulnerable driver names (extend from loldrivers.io)
  OR img LIKE """*\\iqvw64.sys""" OR img LIKE """*\\rtcore64.sys""" OR img LIKE """*\\dbutil_2_3.sys""" OR img LIKE """*\\gdrv.sys"""
  OR img LIKE """*\\aswarpot.sys""" OR img LIKE """*\\truesight.sys""" OR img LIKE """*\\viragt64.sys"""
  OR img LIKE """*\\wnbios*.sys""" OR img LIKE """*\\mhyprot*.sys""" OR img LIKE """*\\zam*.sys""" OR img LIKE """*\\kprocesshacker.sys"""
  OR img LIKE """*\\nscm.sys""" OR img LIKE """*\\nsecsoft*.sys"""
     // or a hash on your vulnerable-driver value list
  OR h IN ("PUT_LOLDRIVERS_HASHES_HERE")
| KEEP @timestamp, host.id, host.name, img, h, dll.name, dll.code_signature.subject_name, dll.pe.original_file_name, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=DriverLoad event_platform=Win
| case {
    ImageFileName=/\\(temp|users|programdata|appdata|downloads|perflogs)\\/i
      ImageFileName!=/\\programdata\\microsoft\\windows defender\\platform\\/i
      | finding := "driver from user-writable path";
    ImageFileName=/\\(iqvw64|rtcore64|dbutil_2_3|gdrv|aswarpot|truesight|viragt64|wnbios.*|mhyprot.*|zam.*|kprocesshacker|nscm|nsecsoft.*)\.sys$/i
      | finding := "known vulnerable driver name";
    in(field="SHA256HashData", ignoreCase=true, values=["PUT_LOLDRIVERS_HASHES_HERE"])
      | finding := "vulnerable driver hash";
  }
| select([@timestamp, aid, ComputerName, finding, ImageFileName, SHA256HashData, OriginalFilename, CertificatePublisher])
```
Populate the hash branch from a scheduled import of the loldrivers.io hash list. Names alone miss renamed drivers; hashes catch them. Keep the hashes lowercase, since `h` is lowercased.

`procexp*.sys` is not on the name list: Process Explorer loads it from `System32\drivers` every time an admin runs it. A copy loaded from a temp or user folder still matches the path branch.

## Suppression
Suppress by `host.id`, `img` for 24h. Alerts missing a key field are not suppressed. Drivers reload at every boot. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Legitimate driver installs from `\Windows\System32\drivers\` under `TrustedInstaller` or a signed installer. The path filter already excludes system paths. Defender platform drivers under `ProgramData\Microsoft\Windows Defender\Platform` are excluded. Hardware vendor drivers installed at imaging time: exclude by hash of the known-good version.
- Hardware tools (CPU-Z, HWiNFO, GPU-Z) extract their drivers to `%TEMP%`. Exclude by hash.

## Triage
- Isolate immediately and pair with W05 (EDR tamper) and W06 (shadow deletion) on the same host: a vulnerable driver load followed by either is a ransomware detonation in progress.

## Test
Load a known loldrivers test driver from `%TEMP%` on a lab host (isolated, non-production).
