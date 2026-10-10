---
id: WE07
name: WDigest re-enabled, LSA protection weakened, LSA packages changed, or DSRM network logon enabled
category: windows-events
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1112, T1003.001, T1685, T1547.002, T1547.005, T1556.002]
data_source: CrowdStrike FDR registry events (RegSystemConfigValueUpdate / AsepValueUpdate / RegGenericValueUpdate)
suppression:
  fields: [host.name, k]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Before dumping credentials, attackers turn `UseLogonCredential` back on so LSASS caches plaintext, or disable RunAsPPL (LSA protection) and Credential Guard so LSASS can be read. These specific registry writes are made by attackers and by almost nothing else. This is the registry precursor to W01.

Two more LSA settings give persistent credential access and are covered here rather than in a separate rule:
- **LSA security, authentication or notification packages:** a DLL added to these lists loads into LSASS at boot. A custom security support provider sees every logon's password, and a rogue password filter sees every password change.
- **`DsrmAdminLogonBehavior` set to 2:** the Directory Services Restore Mode administrator, a local account on every DC, can then log on over the network. Paired with a DSRM password reset (WE03), it is a DC backdoor that survives domain password resets.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action IN ("RegSystemConfigValueUpdate", "AsepValueUpdate", "RegGenericValueUpdate", "RegistryOperationDetectInfo")
  AND host.os.type == "windows"
// registry.path is RegObjectName\RegValueName. String data is in registry.data.strings; DWORD data is only in
// crowdstrike.RegNumericValue, which the integration does not map to ECS (registry.value is the value NAME).
| EVAL k = TO_LOWER(TO_STRING(COALESCE(registry.path, registry.key))),
       num = TO_STRING(crowdstrike.RegNumericValue),
       v = TO_LOWER(MV_CONCAT(TO_STRING(registry.data.strings), " "))
| WHERE (k LIKE """*securityproviders\\wdigest\\uselogoncredential""" AND num == "1")
   OR (k LIKE """*control\\lsa\\runasppl""" AND num == "0")
   OR (k LIKE """*control\\lsa\\lsacfgflags""" AND num == "0")                     // Credential Guard off
   OR (k LIKE """*deviceguard\\lsacfgflags""" AND num == "0")                        // same, by policy
   OR (k LIKE """*control\\lsa\\disablerestrictedadmin""" AND num == "0")          // enables pass-the-hash over RDP
   OR (k LIKE """*control\\lsa\\dsrmadminlogonbehavior""" AND num == "2")
   OR k LIKE """*control\\lsa\\security packages"""
   OR k LIKE """*control\\lsa\\osconfig\\security packages"""
   OR k LIKE """*control\\lsa\\authentication packages"""
   OR k LIKE """*control\\lsa\\notification packages"""
| KEEP @timestamp, host.name, user.name, k, num, v, process.name, process.command_line
```
Value checks are exact, so a hardening write (for example `RunAsPPL` set to 1 by Group Policy) does not match. `crowdstrike.RegNumericValue` is not in the integration's predefined fields; the query fails with "Unknown column" until an FDR registry event carrying it has been indexed. Confirm the field name in your FDR data first.

This is a registry rule, so it runs on FDR, not the Windows Security channel. It belongs with the credential-access group but is grouped here because it is the registry twin of the event-log credential signals.

## Suppression
Suppress by `host.name`, `k` for 24h. Alerts missing a key field are not suppressed. Configuration tools re-apply registry values.

## Known false positives / exclusions
- Legacy applications that require WDigest. Rare and should be eliminated; if one exists, exclude that host explicitly and track it as risk debt.
- Some products add LSA packages at install: password-sync and password-protection agents (notification packages) and some smart card or SSO products (authentication packages). Record the expected values per host role and exclude the exact value, never the key.

## Triage
- Isolate. A WDigest re-enable followed by a logon and an LSASS access (W01) is credential theft in progress. Rotate credentials used on the host.
- For an LSA package change, compare the new list with the default and capture the added DLL from `System32`. A package change on a DC means every password in the domain may be exposed from that DC.
- For `DsrmAdminLogonBehavior`, set it back to 0 and reset the DSRM password on that DC.

## Test
Set `UseLogonCredential` to 1 on a lab host and revert.
