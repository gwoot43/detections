---
id: W14
name: Microsoft Defender for Endpoint high-severity alerts as first-class alerts
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-m365_defender.alert-*
mitre: [various]
data_source: Microsoft Defender XDR alerts (Elastic M365 Defender integration, alert data stream, Graph security alerts v2)
suppression:
  fields: [event.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
This is the Defender counterpart to **CS04**. Defender for Endpoint's behavioural detections are tuned by Microsoft and arrive with a title, a MITRE technique, the device, the user, and a link to the portal. Promoting the high-severity ones to Elastic alerts gives a second EDR opinion beside Falcon with no authoring. The Sense sensor runs even when Defender AV is passive, so these alerts still arrive on Falcon-protected hosts.

The rule is scoped to **endpoint** alerts (`service_source` is Defender for Endpoint). The same stream also carries Defender for Office 365, Defender for Identity, Entra ID Protection and Defender for Cloud Apps alerts, which overlap with the email, identity and Entra rules here. If you want any of those as passthroughs, add their `service_source` value deliberately and drop the overlapping rule, rather than taking everything.

Antivirus and SmartScreen detections are excluded because **WE10** covers them from the local Defender log with tighter filtering. If you don't collect the Defender stream, delete that line so AV detections come through here instead.

## Query
```esql
FROM logs-m365_defender.alert-* METADATA _id, _index, _version
| EVAL svc = TO_LOWER(COALESCE(m365_defender.alert.service_source, "")),
       det_source = TO_LOWER(COALESCE(m365_defender.alert.detection_source, "")),
       sev = TO_LOWER(COALESCE(m365_defender.alert.severity, "")),
       status = TO_LOWER(COALESCE(m365_defender.alert.status, "")),
       verdict = TO_LOWER(COALESCE(m365_defender.alert.classification, ""))
| WHERE svc == "microsoftdefenderforendpoint"
  AND sev == "high"
  AND NOT det_source IN ("antivirus", "smartscreen")
  AND status != "resolved" AND verdict NOT IN ("falsepositive", "informationalexpectedactivity")
| KEEP @timestamp, event.id, m365_defender.alert.title, m365_defender.alert.category, sev, det_source, status,
       m365_defender.alert.mitre_techniques, host.hostname, user.name, m365_defender.alert.incident_id, event.url
```
As with CS04, send **medium** alerts to a lower-priority queue rather than dropping them. Copy the rule with `sev == "medium"` at medium severity. Medium Defender for Endpoint alerts such as "Suspicious PowerShell command line" are often the first step of a chain the correlation rules (X01, X05) build on.

## Suppression
Suppress by `event.id` for 24h. Alerts missing a key field are not suppressed. The integration re-collects an alert every time it is updated (status changes, new evidence, assignment), so the same Defender alert can arrive several times. `event.id` is the Defender alert ID, so each alert fires once.

## Known false positives / exclusions
- Defender alerts are already tuned. Don't re-filter them here. Fix false positives at the source with a Defender suppression rule or indicator allow, so the portal and Elastic agree.
- Alerts an analyst has already classified as false positive or expected activity in the portal are dropped by the `verdict` filter when the update arrives.

## Triage
- Open `event.url` for Microsoft's process tree and evidence, then pivot into FDR in Elastic for the same host and time (`host.hostname`). Falcon telemetry is usually richer for the surrounding activity.
- Check whether Falcon raised a matching detection (CS04). Both firing raises confidence. Defender alone firing on a Falcon-protected host is worth a closer look at why Falcon missed it.

## Test
In the Defender portal, run the built-in detection test on an onboarded lab device (the PowerShell snippet under **Settings > Endpoints > Onboarding**). It raises a test alert. Temporarily allow `sev == "medium"` to see it land.
