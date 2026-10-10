---
id: CP02
name: Quarantine release of malware or high-confidence phish, or release at volume
category: controlplane
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1685, T1566]
data_source: Microsoft 365 Unified Audit Log (quarantine operations and TIMailData records)
suppression:
  fields: [usr]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Releasing a message from quarantine puts it back in the user's inbox. Releasing one that Defender quarantined as malware or high-confidence phishing, or releasing many messages at once, undoes the protection and is how a tricked admin or a malicious insider delivers a payload. Releases are infrequent and attributable. Previews and exports are not releases and are not counted.

## Query
Run hourly with a 7-day lookback. The release record carries no verdict, so the query looks up the message's original `TIMailData` record by network message ID; the long lookback is what lets it find a message quarantined days before the release. Only releases from the last hour are counted, so a release alerts once.
```esql
FROM logs-o365.audit-*
| WHERE event.action IN ("QuarantineRelease", "Release-QuarantineMessage", "TIMailData")
| EVAL is_release = event.action != "TIMailData",
       msg = COALESCE(o365.audit.NetworkMessageId, event.id),
       usr = TO_LOWER(o365.audit.UserId),
       verdict = TO_LOWER(COALESCE(o365.audit.Verdict, "")),
       policy = TO_LOWER(COALESCE(o365.audit.Policy, "")),
       confidence = TO_LOWER(COALESCE(o365.audit.PhishConfidenceLevel, ""))
| EVAL malicious = NOT is_release AND (verdict == "malware" OR policy IN ("antimalware", "highconfidencephish")
                                       OR (verdict == "phish" AND confidence == "high"))
| WHERE NOT is_release OR @timestamp >= NOW() - 1 hour
// one row per message: who released it in the last hour, and whether Defender rated it malicious
| STATS released_by = VALUES(CASE(is_release, usr, NULL)), bad = MAX(CASE(malicious, 1, 0)),
        verdicts = VALUES(CASE(malicious, verdict, NULL)), subject = VALUES(o365.audit.Subject)
    BY msg
| WHERE released_by IS NOT NULL
| MV_EXPAND released_by
| STATS releases = COUNT(*), malicious_releases = SUM(bad),
        verdicts = VALUES(verdicts), subjects = VALUES(subject)
    BY usr = released_by
| WHERE malicious_releases >= 1 OR releases >= 20
```
`QuarantineRelease` is the portal action and `Release-QuarantineMessage` the cmdlet. A message the cmdlet record does not tie to a network message ID still counts toward volume (it is keyed on the record ID) but cannot be matched to a verdict.

## Suppression
Suppress by `usr` for 6h. Alerts missing a key field are not suppressed. Aggregating rule. A release spree spans runs; a different admin still alerts.

## Known false positives / exclusions
- The mail-operations team releasing confirmed false positives. Expected at low volume, but a release of a malware or high-confidence-phish message is reviewed every time; keep that branch.
- End-user self-release where your policy allows it. End users cannot release malware or high-confidence phish by default, so self-release mostly affects the volume branch.

## Triage
- Pull the released message and its verdict. If it was malware or high-confidence phishing, purge it again from all recipients, check whether anyone clicked (E01, E04), and confirm the admin intended the release.

## Test
Release a benign quarantined test message in a lab tenant and confirm it appears in `releases`.
