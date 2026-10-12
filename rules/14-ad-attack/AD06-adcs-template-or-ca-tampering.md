---
id: AD06
name: AD CS template, CA configuration or certificate-mapping enforcement weakened
category: ad-attack
status: todo
severity: high
rank: 6
language: esql
index: logs-system.security*, logs-windows.forwarded*, logs-crowdstrike.fdr-*
mitre: [T1649, T1484]
data_source: Windows Security 5136 (DCs) and AD CS audit events (CA), CrowdStrike FDR process and registry events
suppression:
  fields: [h, finding]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
I09 catches a certificate being issued for someone else. This catches the configuration changes that make that possible in the first place, which are rare administrative actions:
- **Template modified (ESC4):** name flags, enrollment flags, EKUs, application policies, issuance requirements or the template's permissions changed.
- **CA security or settings changed (ESC7 and others):** CA permissions (4882), audit filter (4885), certificate manager settings (4890), configuration entries (4891) or properties (4892).
- **CA flags changed with certutil (ESC6, ESC11, ESC16):** `EditFlags`, `InterfaceFlags` or `DisableExtensionList` set.
- **Certificate mapping enforcement weakened on a DC (ESC9, ESC10):** the KDC's strong certificate binding enforcement or Schannel's certificate mapping methods changed.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded*, logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.code IN ("5136", "4882", "4885", "4890", "4891", "4892")
   OR event.action IN ("ProcessRollup2", "AsepValueUpdate", "RegGenericValueUpdate", "RegSystemConfigValueUpdate")
// Windows events: winlog.computer_name (with event forwarding, host.name is the collector); FDR: host.name
| EVAL h = TO_LOWER(MV_FIRST(SPLIT(COALESCE(winlog.computer_name, host.name), "."))),
       cls = TO_LOWER(COALESCE(TO_STRING(winlog.event_data.ObjectClass), "")),
       attr = TO_LOWER(COALESCE(TO_STRING(winlog.event_data.AttributeLDAPDisplayName), "")),
       cl = TO_LOWER(COALESCE(process.command_line, "")),
       pname = TO_LOWER(COALESCE(process.name, "")),
       regpath = TO_LOWER(COALESCE(TO_STRING(registry.path), "")),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, user.name, ""))
| EVAL template_change = event.code == "5136" AND cls == "pkicertificatetemplate"
          AND attr IN ("mspki-certificate-name-flag", "mspki-enrollment-flag", "pkiextendedkeyusage",
                       "mspki-certificate-application-policy", "mspki-ra-signature", "ntsecuritydescriptor"),
       ca_setting_change = event.code IN ("4882", "4885", "4890", "4891", "4892"),
       ca_flag_change = event.action == "ProcessRollup2" AND pname == "certutil.exe" AND cl LIKE "*-setreg*"
          AND (cl LIKE "*editflags*" OR cl LIKE "*interfaceflags*" OR cl LIKE "*disableextensionlist*"),
       mapping_weakened = event.action IN ("AsepValueUpdate", "RegGenericValueUpdate", "RegSystemConfigValueUpdate")
          AND (regpath LIKE "*kdc*strongcertificatebindingenforcement*"
               OR regpath LIKE "*schannel*certificatemappingmethods*")
| WHERE template_change OR ca_setting_change OR ca_flag_change OR mapping_weakened
| EVAL finding = CASE(template_change, "template_modified",
                      ca_setting_change, "ca_setting_changed",
                      ca_flag_change, "ca_flags_changed",
                      "certificate_mapping_weakened")
| KEEP @timestamp, h, actor, finding, event.code, winlog.event_data.ObjectDN, attr, process.command_line, registry.path, _id, _version, _index
```
Template changes need directory-object auditing on the Certificate Templates container. The CA events need CA auditing for configuration and security changes.

## Suppression
Suppress by `h`, `finding` for 1h. Alerts missing a key field are not suppressed. One template edit writes several attribute changes; a different host or finding still alerts.

## Known false positives / exclusions
- Planned PKI work by the certificate team. Confirm against change control; exclude a named PKI admin account only with a ticket-bound window.
- Template publishing during a new deployment. Expected once.
- The mapping branch matches any write to the two registry values, including raising enforcement. Read the new value in the FDR event before escalating.

## Triage
- Read what changed. A template that now lets the requester supply the subject, a CA with `EditFlags` changed, or mapping enforcement lowered on a DC are each direct escalation paths. Revert, then check I09 for certificates issued while the change was live.

## Test
Change a test template's enrollment flags in a lab and revert it.
