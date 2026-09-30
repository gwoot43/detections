# Detection Library

Starter detection content for a new detection & response function. Stack: **CrowdStrike Falcon** (full FDR ingested), **Mimecast**, **Microsoft 365 / Entra**, **Azure**, **F5 APM** (VPN), **Imperva WAF**, **Zscaler**, all in **Elastic** following **ECS**. Queries are **ES|QL** unless a rule needs **EQL**. Coverage is mapped to **MITRE ATT&CK**.

## Layout
```
rules/
  01-cloud/            C01-C11   Azure & Entra activity/identity-plane
  02-email/            E01-E10   Mimecast + O365 / Defender for Office
  03-endpoint-windows/ W01-W10   CrowdStrike FDR (Windows)
  04-endpoint-linux/   L01-L10   CrowdStrike FDR (Linux)
  05-identity/         I01-I10   Active Directory + authentication (hybrid)
  06-network/          N01-N10   F5 APM, Imperva WAF, Zscaler
  07-crowdstrike-fdr/  CS01-CS08 Falcon sensor-native telemetry (bonus)
  08-correlation/      X01-X05   cross-source chains (highest value)
  09-entra-signin-extended/ S01-S10  additional high-fidelity Entra sign-on signals
  10-windows-event-logs/    WE01-WE10 Windows Security/System event-code detections
docs/
  IMPLEMENTATION-TRACKER.md      tick-off checklist + build order
  NEW-TTPS-2026.md               recent tradecraft & MITRE v18/v19 changes
```

Each rule file is self-contained: front-matter (id, severity, MITRE, data source), a "why this is high fidelity" note, the ES|QL/EQL query, known false positives and exclusions, triage steps, and a test method.

## Design principles (why these are high fidelity, not the AI-noise you have now)
1. **Alert on the improbable, not the merely suspicious.** Every rule targets behaviour with a small, knowable legitimate population you can exclude by name, not by guesswork.
2. **Prefer the transition over the state.** Block-then-success (C11, N02, N06), spray-then-success (I05), disable-then-destroy (X05). Sequences are far cleaner than single events.
3. **Correlate across domains.** The X-series turns two medium signals into one certain one. These are the rules that justify having everything in Elastic.
4. **Exclude by identity, never by muting a technique.** Exclusions are service accounts, pipelines and known hosts, kept in lookups, never "turn the rule off because it's noisy".
5. **Vendor alerts are inputs, not the whole story.** CS04 routes Falcon detections in on day one; the custom rules cover what the vendors cannot see (non-endpoint sources and cross-source chains).

## Field-name caveat
Some sources are not natively ECS (F5, Imperva, Mimecast SIEM logs, some Entra properties nested under `azure.*.properties`). Queries use the closest ECS name and flag where you must confirm the real field in your ingest pipeline. Treat the queries as correct logic to be field-mapped, not copy-paste-final.

## Getting started
See `docs/IMPLEMENTATION-TRACKER.md`. Start with Phase 0 (Falcon passthrough + visibility protection + shared lookups), then Identity/Cloud P1, then Endpoint P1, then Email/Network P1, then the correlation rules.

## MITRE ATT&CK coverage map

| Rule | Technique(s) | Tactic (v19) |
|---|---|---|
| C01 | T1484.002 | Privilege Escalation / Persistence |
| C02 | T1556.009, T1562.007 | Defense Impairment / Credential Access |
| C03 | T1098.003, T1078.004 | Persistence / Privilege Escalation |
| C04 | T1098.001, T1550.001 | Persistence / Lateral Movement |
| C05 | T1528, T1098.001 | Credential Access / Persistence |
| C06 | T1098.003 | Privilege Escalation |
| C07 | T1651, T1098, T1021.008 | Execution / Lateral Movement |
| C08 | T1562.007, T1133 | Defense Impairment / Initial Access |
| C09 | T1562.008, T1685.002 | Defense Impairment |
| C10 | T1530, T1552, T1005 | Collection / Credential Access |
| C11 | T1621, T1528, T1078.004, T1556.009 | Credential Access / Initial Access |
| E01 | T1566.002, T1204.001 | Initial Access / Execution |
| E02 | T1566.001, T1204.002 | Initial Access / Execution |
| E03 | T1656, T1534, T1566.003 | Initial Access / Lateral Movement |
| E04 | T1566.001/.002 | Initial Access |
| E05 | T1204.001, T1566.002 | Execution / Initial Access |
| E06 | T1114.003, T1564.008 | Collection / Stealth |
| E07 | T1114.003 | Collection |
| E08 | T1098.002 | Persistence |
| E09 | T1534, T1114, T1078.004 | Lateral Movement / Collection |
| E10 | T1562.001, T1685, T1078 | Defense Impairment |
| W01 | T1003.001 | Credential Access |
| W02 | T1204.002, T1566.001, T1059 | Execution |
| W03 | T1204.004, T1059.001, T1105 | Execution / Command and Control |
| W04 | T1105, T1218.005/.010, T1197, T1059.001 | Execution / Stealth |
| W05 | T1562.001, T1685, T1068 | Defense Impairment |
| W06 | T1490, T1485 | Impact |
| W07 | T1136.001, T1098, T1021.001, T1562.004 | Persistence / Defense Impairment |
| W08 | T1021.002, T1047, T1021.006/.003, T1053.005, T1569.002 | Lateral Movement / Execution |
| W09 | T1087.002, T1482, T1558.003, T1003, T1069.002, T1018 | Discovery / Credential Access |
| W10 | T1219, T1572, T1090, T1105 | Command and Control |
| L01 | T1059.004, T1071 | Execution / Command and Control |
| L02 | T1105, T1059.004, T1140 | Execution / Command and Control |
| L03 | T1505.003, T1190, T1059.004 | Persistence / Initial Access |
| L04 | T1053.003, T1543.002, T1546.004, T1098.004 | Persistence |
| L05 | T1003.008, T1552.004/.005/.001 | Credential Access |
| L06 | T1548.001/.003, T1068 | Privilege Escalation |
| L07 | T1070.002/.003/.006, T1562.001, T1222.002 | Stealth / Defense Impairment |
| L08 | T1611, T1610, T1613 | Privilege Escalation / Execution |
| L09 | T1547.006, T1014, T1205.002 | Persistence / Stealth |
| L10 | T1486, T1485, T1490 | Impact |
| I01 | T1003.006 | Credential Access |
| I02 | T1098, T1078.002 | Persistence / Privilege Escalation |
| I03 | T1558.003 | Credential Access |
| I04 | T1558.004, T1098 | Credential Access / Persistence |
| I05 | T1110.003 | Credential Access |
| I06 | T1078.002, T1021 | Privilege Escalation / Lateral Movement |
| I07 | T1078.004, T1550.001, T1621 | Initial Access / Credential Access |
| I08 | T1528, T1621, T1078.004 | Credential Access / Initial Access |
| I09 | T1649 | Credential Access |
| I10 | T1556.006, T1098.005 | Defense Impairment / Persistence |
| N01 | T1133, T1078 | Initial Access |
| N02 | T1110, T1133 | Credential Access / Initial Access |
| N03 | T1133, T1078, T1556 | Initial Access / Defense Impairment |
| N04 | T1556, T1562.001, T1078 | Defense Impairment |
| N05 | T1190, T1059 | Initial Access / Execution |
| N06 | T1190, T1595.002 | Initial Access / Reconnaissance |
| N07 | T1071, T1105, T1571 | Command and Control |
| N08 | T1567, T1048, T1041 | Exfiltration |
| N09 | T1090.003, T1572, T1573 | Command and Control |
| N10 | T1595.001, T1046, T1210 | Reconnaissance / Discovery |
| CS01 | T1068, T1211, T1562.001 | Privilege Escalation / Defense Impairment |
| CS02 | T1547.001, T1543.003, T1546 | Persistence |
| CS03 | T1071.004, T1568.002, T1572 | Command and Control |
| CS04 | (various, from Falcon) | (various) |
| CS05 | T1562.001, T1070 | Defense Impairment |
| CS06 | T1055, T1055.012, T1620 | Stealth |
| CS07 | T1053.005, T1543.003 | Persistence / Execution |
| CS08 | (reference) | (reference) |
| X01 | T1566, T1204, T1059 | Initial Access -> Execution |
| X02 | T1078.004, T1098, T1528, T1114.003 | Initial Access -> Persistence |
| X03 | T1133, T1021, T1078 | Initial Access -> Lateral Movement |
| X04 | T1190, T1505.003, T1059 | Initial Access -> Execution |
| X05 | T1486, T1490, T1562.001, T1489 | Impact |
| S01 | T1078.004 | Initial Access |
| S02 | T1078.004, T1110.003, T1556.006 | Credential Access / Defense Impairment |
| S03 | T1078.004, T1556.006 | Initial Access / Defense Impairment |
| S04 | T1087.004, T1526, T1078.004 | Discovery |
| S05 | T1078.004, T1528, T1110 | Credential Access |
| S06 | T1078.004, T1003.006, T1098 | Credential Access / Persistence |
| S07 | T1550.001, T1557, T1078.004 | Lateral Movement / Credential Access |
| S08 | T1550.004, T1539, T1078.004 | Lateral Movement |
| S09 | T1078.004, T1110 | Credential Access |
| S10 | T1078.004, T1090.003 | Initial Access / Command and Control |
| WE01 | T1070.001 | Stealth |
| WE02 | T1562.002 | Defense Impairment |
| WE03 | T1484.001, T1134.005, T1098 | Privilege Escalation / Persistence |
| WE04 | T1110, T1078, T1550.002 | Credential Access |
| WE05 | T1134, T1078.002, T1068 | Privilege Escalation |
| WE06 | T1484.001, T1078.002 | Privilege Escalation |
| WE07 | T1112, T1003.001, T1562.001 | Credential Access / Defense Impairment |
| WE08 | T1543.003, T1569.002, T1068 | Persistence / Execution |
| WE09 | T1003.003 | Credential Access |
| WE10 | T1562.001, T1059, T1204 | Defense Impairment / Execution |

Total: 94 detections across 10 groups. Import into ATT&CK Navigator for a visual heat map; note the v19 Defense Evasion split (see docs/NEW-TTPS-2026.md).
