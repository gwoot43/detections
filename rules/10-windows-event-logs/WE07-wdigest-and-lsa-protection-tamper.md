---
id: WE07
name: WDigest re-enabled, LSA protection disabled, or credential-guard registry weakened
category: windows-events
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1112, T1003.001, T1562.001]
data_source: CrowdStrike FDR registry events (AsepValueUpdate / RegGenericValueUpdate)
---
## Why this is high fidelity
Before dumping credentials, attackers turn `UseLogonCredential` back on so LSASS caches plaintext, or disable RunAsPPL (LSA protection) and Credential Guard so LSASS can be read. These specific registry writes are made by attackers and by almost nothing else. This is the registry precursor to W01.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action IN ("AsepValueUpdate", "RegGenericValueUpdate", "RegistryOperationDetectInfo") AND host.os.type == "windows"
| EVAL k = TO_LOWER(TO_STRING(COALESCE(registry.path, registry.key))),
       v = TO_LOWER(TO_STRING(COALESCE(registry.data.strings, registry.value)))
| WHERE (k LIKE "*securityproviders\\wdigest\\uselogoncredential*" AND v LIKE "*1*")
   OR (k LIKE "*control\\lsa\\runasppl*" AND (v LIKE "*0*"))
   OR (k LIKE "*lsa\\lsacfgflags*" AND v LIKE "*0*")
   OR (k LIKE "*deviceguard*" AND k LIKE "*lsacfg*" AND v LIKE "*0*")
   OR (k LIKE "*control\\lsa\\disablerestrictedadmin*" AND v LIKE "*0*")
   OR (k LIKE "*control\\lsa\\restrictedadmin*" AND v LIKE "*0*")
   OR (k LIKE "*wow6432node*securityproviders\\wdigest\\uselogoncredential*" AND v LIKE "*1*")
| KEEP @timestamp, host.name, user.name, k, v, process.name, process.command_line
```
This is a registry rule, so it runs on FDR, not the Windows Security channel. It belongs with the credential-access group but is grouped here because it is the registry twin of the event-log credential signals.

## Known false positives / exclusions
- Legacy applications that require WDigest. Rare and should be eliminated; if one exists, exclude that host explicitly and track it as risk debt.

## Triage
- Isolate. A WDigest re-enable followed by a logon and an LSASS access (W01) is credential theft in progress. Rotate credentials used on the host.

## Test
Set `UseLogonCredential` to 1 on a lab host and revert.
