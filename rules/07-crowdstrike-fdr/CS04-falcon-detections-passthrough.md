---
id: CS04
name: CrowdStrike Falcon platform detections (high/critical) as first-class alerts
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.alert-*
mitre: [various]
data_source: CrowdStrike Falcon detections / EPP alerts (Elastic CrowdStrike integration)
suppression:
  fields: [host.name, technique]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Falcon's own detections are already tuned by CrowdStrike and carry a confidence and a tactic. Routing high and critical Falcon detections into Elastic as alerts on day one gives you immediate, high-quality coverage of the endpoint domain with zero authoring. This is the single fastest coverage win. Do it first.

## Query
```esql
FROM logs-crowdstrike.alert-* METADATA _id, _index, _version
| EVAL sev = TO_LOWER(COALESCE(crowdstrike.alert.severity_name, "")),
       product = TO_LOWER(COALESCE(crowdstrike.alert.product, "")),
       status = TO_LOWER(COALESCE(crowdstrike.alert.status, "")),
       tactic = COALESCE(crowdstrike.alert.tactic, ""),
       technique = COALESCE(crowdstrike.alert.technique_id, ""),
       // endpoint (epp) alerts only fill host.hostname; identity and NG-SIEM alerts fill host.name
       host.name = COALESCE(host.name, host.hostname)
// OverWatch notifications carry no severity and are always worth a page
| WHERE (sev IN ("high", "critical") OR product == "overwatch")
  // the integration re-collects an alert on every update; a closing update must not re-page
  AND status != "closed"
| KEEP @timestamp, host.name, user.name, product, sev, crowdstrike.alert.display_name, crowdstrike.alert.description, tactic, technique,
       crowdstrike.alert.pattern_disposition_description, process.name, process.command_line, event.id
```
Also feed medium detections into a lower-priority queue rather than dropping them; they feed the correlation rules (X-series) even when not alertable on their own.

The severity comes from Falcon's own `severity_name`, which is what the console shows. The numeric `crowdstrike.alert.severity` is a different type (long) and cannot be mixed into the same `COALESCE`.

## Suppression
Suppress by `host.name`, `technique` for 1h. Alerts missing a key field are not suppressed. Falcon may raise several detections for one behaviour. `host.name` here is filled from `host.hostname` when the alert has no `host.name`. `technique` is empty rather than missing for OverWatch alerts, so they group per host.

## Known false positives / exclusions
- Falcon detections are already tuned; do not re-filter aggressively. Suppress specific known-benign pattern dispositions only after review with the Falcon console.

## Triage
- Use the Falcon detection as the anchor and enrich with the surrounding FDR telemetry in Elastic (process tree, network, DNS). This is where ingesting the whole FDR feed pays off: the alert comes from Falcon, the investigation happens in Elastic.

## Test
Run an EICAR or a benign Atomic that Falcon detects and confirm the detection lands in Elastic.
