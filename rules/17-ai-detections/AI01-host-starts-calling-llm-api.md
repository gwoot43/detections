---
id: AI01
name: Host starts calling a public LLM API directly (malware or an agent using an AI model at runtime)
category: ai
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1588.007, T1071.001]
data_source: CrowdStrike FDR DnsRequest (Zscaler web logs as an alternative, see below)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Malware has started asking public AI models what to do next. APT28's LAMEHUG sends a task to a model on Hugging Face and runs the commands that come back, so there's nothing malicious in the file to scan for. ATT&CK lists this under T1588.007. People use AI in a browser, through the chat sites (`chatgpt.com`, `claude.ai`, `gemini.google.com`). A program calling a model directly uses the providers' API endpoints instead (`api.openai.com`, `api.anthropic.com`, `router.huggingface.co` …), and on most hosts nothing does.

- **Anchor:** a DNS lookup of a public LLM provider's API endpoint (the list in the query; the chat websites aren't on it).
- **Corroborating property:** the host is new to this API. Its first lookup of it in the 7-day lookback was in the last 2 hours. Developers and tools that use the API every day have a history.
- **Exclusion by rarity of the start:** at most 3 hosts started on the same API in those 2 hours. A software rollout that adds an AI feature starts many hosts at once and drops out.

FDR DNS events carry the process ID but often not the process name, so the alert names the host and the process ID. The LogScale triage step below names the program.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Anchor: lookups in the LLM providers' domains (cheap, indexed), narrowed below to their API endpoints.
| WHERE event.action == "DnsRequest"
  AND dns.question.registered_domain IN ("openai.com", "anthropic.com", "googleapis.com", "huggingface.co", "mistral.ai", "deepseek.com",
                                         "openrouter.ai", "groq.com", "together.xyz", "x.ai", "cohere.com", "cohere.ai", "perplexity.ai")
| EVAL dns.question.name = TO_LOWER(dns.question.name)
// The API endpoints a program calls. The chat websites people use in a browser aren't here.
| WHERE dns.question.name IN ("api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "router.huggingface.co",
                              "api-inference.huggingface.co", "api.mistral.ai", "api.deepseek.com", "openrouter.ai", "api.groq.com",
                              "api.together.xyz", "api.x.ai", "api.cohere.com", "api.cohere.ai", "api.perplexity.ai")
// One row per host and API: when the host first looked it up in the 7 days.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), lookups = COUNT(*),
        process.entity_id = VALUES(process.entity_id), process.name = VALUES(process.name), host.name = VALUES(host.name)
    BY host.id, dns.question.name
// Hosts that started on this API in the last 2 hours: a rollout starts many at once.
| EVAL started_now = CASE(first_seen >= NOW() - 2 hours, host.id, NULL)
| INLINE STATS new_hosts = COUNT_DISTINCT(started_now) BY dns.question.name
// New for this host, and at most 3 hosts started on this API together.
| WHERE first_seen >= NOW() - 2 hours AND new_hosts <= 3
// One alert per host, listing every API it started on.
| STATS first_seen = MIN(first_seen), last_seen = MAX(last_seen), lookups = SUM(lookups), dns.question.name = VALUES(dns.question.name),
        process.entity_id = VALUES(process.entity_id), process.name = VALUES(process.name), host.name = VALUES(host.name)
    BY host.id
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=DnsRequest
// Anchor: the LLM providers' API endpoints a program calls. The chat websites people use in a browser aren't here.
| in(field="DomainName", ignoreCase=true, values=["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
                                                 "router.huggingface.co", "api-inference.huggingface.co", "api.mistral.ai",
                                                 "api.deepseek.com", "openrouter.ai", "api.groq.com", "api.together.xyz", "api.x.ai",
                                                 "api.cohere.com", "api.cohere.ai", "api.perplexity.ai"])
| DomainName := lower(DomainName)
// One row per host and API: when the host first looked it up in the 7 days.
| groupBy([aid, DomainName], function=[min(@timestamp, as=first_seen), count(as=lookups), collect([ComputerName, ContextProcessId])], limit=max)
// New for this host in the last 2 hours.
| _now := now()
| test(first_seen > _now - 7200000)
// One row per API, counting the hosts that started on it together: a rollout starts many at once.
| groupBy([DomainName], function=[count(aid, distinct=true, as=new_hosts), collect([aid, ComputerName, ContextProcessId])])
| test(new_hosts <= 3)
```

**Alternative source (Zscaler):** the same API endpoints in `url.domain`, grouped by `user.name` instead of host, cover devices without Falcon. `user_agent.original` then stands in for the program (`python-requests`, `OpenAI/Python`, `node-fetch` …). LAMEHUG was compiled Python, so its requests carry Python's user agent.

**Check before deploying:** the endpoint list is the providers we know of; add any your organisation uses (an Azure OpenAI endpoint of your own is `<name>.openai.azure.com` and belongs in a separate rule, since your apps use it every day). In your own index, `dns.question.name` may end with a dot; strip it before the `IN`.

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and a host alerts once, when it starts.

## Known false positives / exclusions
- A developer trying a new provider or SDK. It alerts once for that host and API, then has a history. On developer workstations that's routine; if it's noisy, exclude your developer hosts by `host.id` and keep the rule for everything else.
- A new AI feature in an application installed on a few hosts. Same: once per host, then history.

## Triage
- Name the program. In LogScale: `#event_simpleName=/ProcessRollup2$/ aid=<host.id> TargetProcessId=<process.entity_id>` gives the path, command line and parent. A Python, PowerShell or unsigned binary in a user folder on a non-developer host is the LAMEHUG pattern.
- See what it did next. Look for the processes it started after each lookup (`ParentProcessId=<process.entity_id>`). Malware that asks a model for commands runs them straight away: discovery (`whoami`, `systeminfo`, `dir`), copying documents, archiving.
- Check where the results went: outbound connections from the same process to anything other than the model's API.

## Test
On a lab Windows host that has never called an LLM API, run `python -c "import urllib.request; urllib.request.urlopen('https://router.huggingface.co')"`. It should alert within the hour, naming `router.huggingface.co`.
