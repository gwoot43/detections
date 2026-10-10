---
id: AD07
name: DNS server plugin DLL configured on a domain controller (DnsAdmins abuse)
category: ad-attack
status: todo
severity: high
rank: 7
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1574, T1068]
data_source: CrowdStrike FDR registry and process events
suppression:
  fields: [host.name]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The DNS Server service loads any DLL named in its `ServerLevelPluginDll` setting, as SYSTEM, when it restarts. On a domain controller that means code execution as SYSTEM on the DC, and members of DnsAdmins, who are not domain admins, can set it. The setting is essentially never used legitimately, so any write to it is a strong signal.

Membership changes to DnsAdmins itself are already covered by I02.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE host.os.type == "windows"
  AND event.action IN ("AsepValueUpdate", "RegGenericValueUpdate", "RegSystemConfigValueUpdate", "ProcessRollup2")
| EVAL regpath = TO_LOWER(COALESCE(TO_STRING(registry.path), "")),
       cl = TO_LOWER(COALESCE(process.command_line, "")),
       pname = TO_LOWER(COALESCE(process.name, ""))
| WHERE (event.action IN ("AsepValueUpdate", "RegGenericValueUpdate", "RegSystemConfigValueUpdate")
         AND regpath LIKE "*services*dns*parameters*serverlevelplugindll*")
     OR (event.action == "ProcessRollup2" AND pname == "dnscmd.exe" AND cl LIKE "*serverlevelplugindll*")
| KEEP @timestamp, host.name, user.name, event.action, regpath, registry.data.strings, process.command_line, process.parent.name
```
The DNS Server event log also records the plugin loading (event 770 in the DNS Server channel) if you ship that channel; it is a useful confirmation during triage.

## Suppression
Suppress by `host.name` for 24h. Alerts missing a key field are not suppressed. The setting is written once and the service restart follows; a different DC still alerts.

## Known false positives / exclusions
- None expected. A small number of DNS add-ons use the plugin interface; if you run one, exclude its exact DLL path inline.

## Triage
- Read the configured DLL path (often a UNC share). Clear the setting, restart DNS from a clean state, and capture the DLL.
- Check who set it and how they got DnsAdmins membership (I02). Treat the DC as compromised if the service has already restarted with the plugin.

## Test
Set and clear the value on a lab DC.
