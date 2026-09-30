---
id: X06
name: External Teams contact followed by remote-access tool on the same user's host
category: correlation
status: todo
severity: high
language: esql
index: logs-*
mitre: [T1566, T1219, T1204]
data_source: Microsoft 365 audit (Teams external chat) + CrowdStrike (W10) joined on user and host
suppression:
  fields: [usr, host.name]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The help-desk social engineering chain: an external-tenant Teams message or call, then the user is talked into running Quick Assist or another remote tool. Either half is individually plausible; an external Teams contact followed within an hour by a remote-access tool launching on that user's host is the Black Basta and 3AM initial-access pattern. You ingest both the Microsoft 365 audit log and full Falcon telemetry, so this is a straightforward join.

## Query (pattern)
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE @timestamp > NOW() - 1 hour AND event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL usr = TO_LOWER(user.name), pname = TO_LOWER(process.name)
| WHERE pname IN ("quickassist.exe", "anydesk.exe", "teamviewer.exe", "screenconnect.windowsclient.exe", "rustdesk.exe", "logmein.exe", "supremo.exe", "zohoassist.exe")
| LOOKUP JOIN teams_external_contacts_last_2h ON usr
| WHERE contact_at IS NOT NULL AND @timestamp >= contact_at
| KEEP @timestamp, usr, host.name, pname, process.command_line, external_domain, contact_at
```
Build `teams_external_contacts_last_2h` from the Microsoft 365 audit log: Teams events for chats or calls with an external federated tenant (fields `usr`, `contact_at`, `external_domain`). If LOOKUP JOIN is unavailable, implement as an indicator-match rule keyed on user with a 1-hour look-back. This overlaps W10 on the endpoint side; the correlation raises its severity and confidence.

## Suppression
Suppress by `usr`, `host.name` for 24h. Alerts missing a key field are not suppressed. Correlation rule; suppression stops repeated matches for the same session.

## Known false positives / exclusions
- Legitimate external support that uses Teams and a remote tool. Exclude your sanctioned support vendors' external domains, and remove your own approved RMM from the process list (it is covered by W10 exclusions).

## Triage
- Call the user. If they were contacted out of the blue and guided to install or run the tool, isolate the host, kill the session, and treat as active intrusion. Review what the remote operator did.

## Test
From a lab external tenant, message a lab user in Teams, then launch Quick Assist on their host within the hour.
