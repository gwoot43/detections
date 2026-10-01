# Control-plane detections

Detections for weakening or blinding the security controls themselves: Defender for Office 365 mail protection, the quarantine, the tenant allow list, and the endpoint sensors (CrowdStrike and Defender). An attacker or a tricked or malicious admin turns these off before or during an intrusion, so a change here is often the earliest warning.

All rules use the Microsoft 365 Unified Audit Log, the Windows Defender operational log, or CrowdStrike sensor-health data. Exclusions are inline; no lookups.

| Rule | Behaviour |
|---|---|
| CP01 | Safe Links, Safe Attachments or anti-phishing policy disabled, deleted or weakened |
| CP02 | Quarantine release of malicious mail, or release at volume |
| CP03 | Tenant Allow/Block List allow entry added (whitelisting attacker infrastructure) |
| CP04 | CrowdStrike sensor in Reduced Functionality Mode or no longer reporting |
| CP05 | Microsoft Defender health degraded or the MDE sensor (Sense) not running |

Data-source notes:
- **CP04** needs Falcon host-status or sensor-health data ingested (via the Falcon API or secondary feeds) for the RFM branch; the not-reporting branch uses only the FDR process stream.
- **CP05** needs the Windows Defender operational channel and the System channel shipped by the Elastic Windows integration; confirm the event codes your Defender build emits.
