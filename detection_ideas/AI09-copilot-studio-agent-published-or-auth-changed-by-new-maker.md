---
id: AI09
name: Copilot Studio agent published or its authentication changed by someone new to it
category: ai
status: todo
severity: medium
language: esql
index: logs-o365.audit-*
mitre: [T1700]
data_source: Microsoft Purview unified audit log via the Elastic O365 integration (Copilot Studio records)
suppression:
  fields: [usr, event.action]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A Copilot Studio agent can be given connectors to mail, SharePoint, HTTP endpoints and other services, and then published for others to chat with. That makes it a ready-made exfiltration tool. Someone with a compromised maker account can publish an agent that sends data out. Or, with authentication switched off, anyone with the link can ask the agent for what it can reach. ATT&CK v20 calls steering an enterprise agent into moving data out AI-Enabled Exfiltration (T1700).

Publishing an agent or changing who can talk to it are rare actions, done by a small group of makers.

- **Anchor:** a Copilot Studio agent published (`BotUpdateOperation-BotPublish`) or its authentication changed (`BotUpdateOperation-BotAuthUpdate`).
- **Corroborating property:** the person is new to it. Their first such action in the 30-day lookback was in the last 2 hours. Regular makers have a history.

## Query
Run hourly with a 30-day lookback (the slice is small: only Copilot Studio admin actions).
```esql
FROM logs-o365.audit-*
// Anchor: a Copilot Studio agent published, or its authentication changed.
| WHERE event.action IN ("BotUpdateOperation-BotPublish", "BotUpdateOperation-BotAuthUpdate")
| EVAL usr = TO_LOWER(o365.audit.UserId)
// One row per person and action: when they first did it in the 30 days, and to which agents.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), times = COUNT(*), o365.audit.ObjectId = VALUES(o365.audit.ObjectId),
        source.ip = VALUES(source.ip)
    BY usr, event.action
// New for this person in the last 2 hours. Regular makers have a history.
| WHERE first_seen >= NOW() - 2 hours
```

**Check before deploying.** The operation names come from Microsoft's Copilot Studio audit documentation; confirm them in your data.
1. Run `FROM logs-o365.audit-* | WHERE event.action LIKE "Bot*" | STATS COUNT(*) BY event.action, event.provider` over 30 days.
2. If nothing comes back, either nobody in your tenant uses Copilot Studio, or its records aren't in your audit feed.
3. If the records are there, look at one `BotUpdateOperation-BotAuthUpdate` record. Find the field that says which authentication the agent now uses. An agent switched to "No authentication" deserves a high-severity branch of its own.

## Suppression
Suppress by `usr`, `event.action` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 30-day lookback overlaps every run, and a person alerts once, when they start.

## Known false positives / exclusions
- A new maker publishing their first agent. It alerts once; check it's someone who's meant to build agents.

## Blind spot
The audit records say an agent was published, not what its connectors send. Seeing the data actually leave needs the Power Platform connector and DLP logs, or the destination's logs (outbound mail, Zscaler for HTTP endpoints).

## Triage
- Is this person a known maker? Check their sign-in for the session (location, device, MFA) for signs of a compromised account (S-series rules).
- Open the agent in Copilot Studio: what knowledge sources and connectors does it have, who can chat with it, and does it require sign-in? An agent with access to mail or SharePoint, sending to an external HTTP endpoint or email address, is the exfiltration pattern.
- If it's unexpected, unpublish it, then review its conversation transcripts (if enabled) for what was asked.

## Test
In a lab environment, have a test account that has never published an agent publish a simple Copilot Studio agent. It should alert within the hour.
