---
id: CS08
name: Reference: push these to Falcon custom IOAs, not just Elastic
category: crowdstrike-fdr
status: todo
severity: info
language: n/a
index: n/a
mitre: []
data_source: CrowdStrike Falcon custom IOA framework
---
## Purpose
Some of the endpoint detections in this library are better enforced at the sensor as custom Indicators of Attack, because Falcon can block in real time rather than alert after the fact in Elastic. Ingesting the full FDR feed means you can prototype the logic in ES|QL, confirm the false-positive rate, then promote the stable ones to custom IOAs for prevention.

## Candidates to promote to Falcon custom IOAs (prevent), keeping the ES|QL version for hunting and correlation
- W01 LSASS dump (comsvcs MiniDump, procdump -ma lsass)
- W03 ClickFix/FileFix (explorer.exe -> script host with URL/encoded command)
- W05 security-tool tamper and W06 shadow-copy deletion
- W08 lateral movement (services.exe/wmiprvse.exe -> shell)
- CS01 BYOVD vulnerable driver load
- L01 reverse shell, L03 web service spawning a shell

## Workflow
1. Run the ES|QL rule in Elastic for two weeks, tune exclusions.
2. Translate the stable logic to a Falcon custom IOA (parent/child image, command-line regex).
3. Set to Detect first, then Prevent once the FP rate is acceptable.
4. Keep the Elastic rule for correlation with non-endpoint sources (the X-series), which Falcon cannot do.

This file is documentation, not a query. It has no alert; it records the prevention plan so endpoint detections are enforced, not just observed.
