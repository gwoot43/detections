---
id: AI04
name: Azure OpenAI keys listed or content filter changed by an identity new to it (LLMjacking)
category: ai
status: todo
language: esql
index: logs-azure.activitylogs-*
mitre: [T1496.004, T1552]
data_source: Azure Activity log
suppression:
  fields: [actor, action]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
"LLMjacking" is stealing access to an organisation's AI models to use them for free, or to generate content the provider would refuse. Storm-2139 took Azure OpenAI keys from victims, switched off the content filters and sold access. ATT&CK lists it under Cloud Service Hijacking (T1496.004). It takes two steps in Azure, and both are rare:

- **Anchor:** an Azure OpenAI (Cognitive Services) account's keys are listed or regenerated, or a content filter (RAI policy) is created, changed or deleted.
- **Corroborating property:** the identity is new to this. Its first such action in the 7-day lookback was in the last 2 hours. Deployment pipelines that read keys on every run have a history and stay quiet.

A content filter change is the stronger signal, since there's rarely a reason to weaken one; `action` says which it was.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-azure.activitylogs-*
// Anchor: AI account keys listed or regenerated, or a content filter (RAI policy) written or deleted. Successes only.
| EVAL op = TO_UPPER(azure.activitylogs.operation_name)
| WHERE op IN ("MICROSOFT.COGNITIVESERVICES/ACCOUNTS/LISTKEYS/ACTION",
               "MICROSOFT.COGNITIVESERVICES/ACCOUNTS/REGENERATEKEY/ACTION",
               "MICROSOFT.COGNITIVESERVICES/ACCOUNTS/RAIPOLICIES/WRITE",
               "MICROSOFT.COGNITIVESERVICES/ACCOUNTS/RAIPOLICIES/DELETE")
  AND event.outcome == "success"
// Who did it (a person, or an app for service principals), and which kind of action.
| EVAL actor = COALESCE(azure.activitylogs.identity.claims_initiated_by_user.name, azure.activitylogs.identity.claims.appid),
       action = CASE(op LIKE "*/RAIPOLICIES/*", "content filter changed", "keys listed or regenerated")
// One row per identity and action: when it first did this in the 7 days.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), times = COUNT(*), operations = VALUES(op),
        azure.resource.name = VALUES(azure.resource.name), azure.subscription_id = VALUES(azure.subscription_id), source.ip = VALUES(source.ip)
    BY actor, action
// New for this identity in the last 2 hours. Pipelines that read keys on every deploy have a history.
| WHERE first_seen >= NOW() - 2 hours
```

**Check before deploying:** run `FROM logs-azure.activitylogs-* | WHERE TO_UPPER(azure.activitylogs.operation_name) LIKE "MICROSOFT.COGNITIVESERVICES/*" | STATS COUNT(*) BY azure.activitylogs.operation_name` over 30 days. That shows whether you run Azure OpenAI or AI Foundry at all, and the exact operation names in your data. AI Foundry projects may log under `MICROSOFT.MACHINELEARNINGSERVICES/*` instead; add their key and connection operations if so.

## Suppression
Suppress by `actor`, `action` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and an identity alerts once, when it starts.

## Known false positives / exclusions
- An engineer setting up a new AI app reads its keys or tunes its content filter. It alerts once; check it against the change record.
- A new deployment pipeline. Once, then history.

## Triage
- Is the identity expected to touch AI resources? Check its sign-in (location, device, MFA) around `first_seen` (S-series rules), and `source.ip`.
- After a key listing, look at the account's usage: token counts and requests in Azure Monitor metrics, and calls from unfamiliar addresses if diagnostic logs are on. Abuse shows as a jump in usage, often outside business hours.
- After a content filter change, compare the policy to the previous one. If it was weakened, put it back, rotate both keys and review who has `Cognitive Services Contributor` on the account.

## Test
In a lab subscription, as an account that hasn't touched the resource this week, open an Azure OpenAI resource's **Keys and Endpoint** page (this lists the keys). The rule should alert within the hour.
