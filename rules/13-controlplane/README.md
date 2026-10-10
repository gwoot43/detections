# Control-plane detections

Detections for weakening or blinding the security controls themselves: Defender for Office 365 mail protection, the quarantine, the tenant allow list, and the endpoint sensors (CrowdStrike and Defender). An attacker or a tricked or malicious admin turns these off before or during an intrusion, so a change here is often the earliest warning.

All rules use the Microsoft 365 Unified Audit Log, the Windows Defender operational log, or CrowdStrike sensor-health data. Exclusions are inline; no lookups.

| Rule | Behaviour |
|---|---|
| CP01 | Safe Links, Safe Attachments or anti-phishing policy disabled, deleted or weakened |
| CP02 | Quarantine release of malicious mail, or release at volume |
| CP03 | Tenant Allow/Block List allow entry added (whitelisting attacker infrastructure) |
| CP04 | CrowdStrike sensor in Reduced Functionality Mode or no longer reporting |
| CP05 | Microsoft Defender engine, platform or signature failure, or the Defender AV or MDE (Sense) service stopped and stayed down |
| CP06 | Microsoft Defender protection weakened: real-time protection off, exclusion added, ASR or network protection off, tamper attempt blocked |

Data-source notes:
- **CP04** reads RFM state straight from FDR: `OsVersionInfo` and `SensorMetadataUpdate` carry it as `crowdstrike.RFMState`, and heartbeats show whether the sensor is still alive. No API feed is needed.
- **CP05** and **CP06** need the **Windows Defender** stream turned on in the Elastic Windows integration (it ships disabled), which writes to `logs-windows.windows_defender-*`. CP05 also reads the System channel (`logs-system.system-*`). Both rules parse the rendered `message`, so they don't depend on event data fields that are only mapped after the first matching event.
- **CP06** sees the *result* of a Defender change however it was made. W05 sees the *command* when Falcon catches it. Detections and Exploit Guard blocks are in WE10.
