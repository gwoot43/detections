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
---
## Why this is high fidelity
Falcon's own detections are already tuned by CrowdStrike and carry a confidence and a tactic. Routing high and critical Falcon detections into Elastic as alerts on day one gives you immediate, high-quality coverage of the endpoint domain with zero authoring. This is the single fastest coverage win. Do it first.

## Query
```esql
FROM logs-crowdstrike.alert-* METADATA _id, _index, _version
| EVAL sev = TO_LOWER(TO_STRING(COALESCE(crowdstrike.alert.severity_name, event.severity))),
       tactic = TO_STRING(COALESCE(threat.tactic.name, crowdstrike.alert.tactic)),
       technique = TO_STRING(COALESCE(threat.technique.id, crowdstrike.alert.technique_id))
| WHERE sev IN ("high", "critical") OR TO_INTEGER(COALESCE(crowdstrike.alert.severity, 0)) >= 70
| KEEP @timestamp, host.name, user.name, crowdstrike.alert.description, tactic, technique, crowdstrike.alert.pattern_disposition, process.name, process.command_line
```
Also feed medium detections into a lower-priority queue rather than dropping them; they feed the correlation rules (X-series) even when not alertable on their own.

## Known false positives / exclusions
- Falcon detections are already tuned; do not re-filter aggressively. Suppress specific known-benign pattern dispositions only after review with the Falcon console.

## Triage
- Use the Falcon detection as the anchor and enrich with the surrounding FDR telemetry in Elastic (process tree, network, DNS). This is where ingesting the whole FDR feed pays off: the alert comes from Falcon, the investigation happens in Elastic.

## Test
Run an EICAR or a benign Atomic that Falcon detects and confirm the detection lands in Elastic.
