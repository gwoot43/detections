---
id: AI10
name: Defender for Cloud alert on your own AI apps (jailbreak, prompt injection, data leak through a model)
category: ai
status: todo
language: esql
index: logs-m365_defender.alert-*
mitre: [T1699, T1698, T1700]
data_source: Microsoft Defender XDR alerts (Elastic M365 Defender integration, alert data stream), raised by Defender for Cloud threat protection for AI services
suppression:
  fields: [event.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
If you build apps on Azure OpenAI or AI Foundry (a chatbot, an internal assistant, an agent), they can be attacked through their prompts. Users or content can try to jailbreak them (T1699), smuggle in hidden instructions (T1698), or get them to hand out sensitive data or credentials (T1700). Defender for Cloud's threat protection for AI services watches the model deployments and raises alerts. It uses Azure AI Content Safety's Prompt Shields and Microsoft's threat intelligence. This rule passes those alerts through, the way W14 does for Defender for Endpoint:

- **Anchor:** Defender XDR alerts from Defender for Cloud.
- **Corroborating property:** the alert type is one of the AI ones, which start with `AI.` (for example a blocked or detected jailbreak attempt, ASCII smuggling, sensitive data in a model's answer, or access from a suspicious address).
- **Exclusion:** alerts already resolved or classified as false positives.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-m365_defender.alert-* METADATA _id, _index, _version
| EVAL svc = TO_LOWER(COALESCE(m365_defender.alert.service_source, "")),
       alert_type = TO_UPPER(COALESCE(m365_defender.alert.detector_id, "")),
       status = TO_LOWER(COALESCE(m365_defender.alert.status, "")),
       verdict = TO_LOWER(COALESCE(m365_defender.alert.classification, ""))
// Anchor: Defender for Cloud alerts on AI workloads, whose alert types start with "AI.".
| WHERE svc == "microsoftdefenderforcloud" AND alert_type LIKE "AI.*"
  // Not already closed as resolved or a false positive.
  AND status != "resolved" AND verdict NOT IN ("falsepositive", "informationalexpectedactivity")
| KEEP @timestamp, event.id, m365_defender.alert.title, alert_type, m365_defender.alert.severity, status,
       m365_defender.alert.description, m365_defender.alert.incident_id, event.url, _id, _version, _index
```

**Check before deploying:**
- This needs Defender for Cloud's threat protection for AI services switched on for the subscriptions that host your AI apps. Their alerts must also flow into Defender XDR, which they do by default.
- Run `FROM logs-m365_defender.alert-* | WHERE TO_LOWER(m365_defender.alert.service_source) == "microsoftdefenderforcloud" | STATS COUNT(*) BY m365_defender.alert.detector_id, m365_defender.alert.title` over 30 days. That confirms the `AI.` alert types land in `detector_id`. If they land elsewhere, match on the titles instead, which mention the "Azure AI model deployment".
- If you don't build apps on Azure AI, this rule has nothing to watch; AI03 covers Microsoft 365 Copilot.

## Suppression
Suppress by `event.id` for 24h (one alert per Defender alert). Alerts missing a key field are not suppressed.

## Known false positives / exclusions
- Your own red-teaming of the app. Classify those alerts in Defender as expected activity and they drop out.

## Triage
- Read the alert: which deployment, which app, and the prompt or response evidence Defender attaches. Defender may show the user or source address.
- A blocked jailbreak from one external user is routine for a public chatbot; repeated attempts, a detected (not blocked) one, or a data-leak alert is not. For a data leak, find what the model returned and who received it.
- For suspicious access, rotate the deployment's keys and check AI04 for who listed them.

## Test
Against a lab Azure OpenAI deployment with Defender for Cloud AI threat protection on, send a known jailbreak prompt through the app. Defender should raise an alert and the rule should pass it through within 15 minutes.
