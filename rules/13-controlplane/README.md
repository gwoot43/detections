# Control-plane detections

Detections for weakening or blinding the security controls themselves: Defender for Office 365 mail protection, the quarantine, the tenant allow list, and the endpoint sensors (CrowdStrike and Defender). An attacker or a tricked or malicious admin turns these off before or during an intrusion, so a change here is often the earliest warning.

All rules use the Microsoft 365 Unified Audit Log, the Windows Defender operational log, or CrowdStrike sensor-health data. Exclusions are inline; no lookups.

| Rule | Behaviour |
|---|---|
| CP01 | Safe Links, Safe Attachments, anti-phishing, anti-malware or anti-spam rule or policy disabled, deleted or switched off, including ZAP turned off |
| CP02 | Quarantine release of malware or high-confidence phish, or release at volume |
| CP03 | Tenant Allow/Block List allow entry added (whitelisting attacker infrastructure) |
| CP04 | CrowdStrike sensor in Reduced Functionality Mode or no longer reporting |
| CP05 | Microsoft Defender engine, platform or signature failure, or the Defender AV or MDE (Sense) service stopped and stayed down |
| CP06 | Microsoft Defender protection weakened: real-time protection off, exclusion added, ASR or network protection off, tamper attempt blocked |

Data-source notes:
- **CP01-CP03** read Exchange cmdlet parameters as `o365.audit.Parameters.<Name>`. Most of those fields are mapped only when a parameter is first used, and a query that names an unmapped field fails. Each rule lists the fields it needs; map them as `keyword` in the `logs-o365.audit@custom` component template. CP02 joins the release to the message's original `TIMailData` record for the verdict.
- **CP04** reads RFM state straight from FDR: `OsVersionInfo` and `SensorMetadataUpdate` carry it as `crowdstrike.RFMState`, and heartbeats show whether the sensor is still alive. No API feed is needed.
- **CP05** and **CP06** need the **Windows Defender** stream turned on in the Elastic Windows integration (it ships disabled), which writes to `logs-windows.windows_defender-*`. CP05 also reads the System channel (`logs-system.system-*`). Both rules parse the rendered `message`, so they don't depend on event data fields that are only mapped after the first matching event.
- **CP06** owns Defender settings changes and sees the *result* however it was made. W05 covers the process side it cannot see (Defender services stopped, engine wiped, safe boot set); Falcon tamper is CS05. Detections and Exploit Guard blocks are in WE10.
