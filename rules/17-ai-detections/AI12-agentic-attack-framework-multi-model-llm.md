---
id: AI12
name: Agentic attack framework driving several LLMs, or a non-sanctioned model, from one host (ARTEX-class)
category: ai
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1588.007, T1071.001]
data_source: CrowdStrike FDR DnsRequest (Zscaler web logs as an alternative, see below)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An agentic pentest framework runs the attack for the operator: an LLM planner decides the next step, a worker runs a tool, the result goes back to the model, and the loop repeats. ARTEX (used by TAG-217 against South Korean banks in 2026) is the current example, and it was run **alongside several models at once** - Claude, DeepSeek, Grok, Zhipu. That is the tell. A developer or a sanctioned AI feature talks to **one** approved provider; a framework juggling **two or more** different models, or reaching a provider your organisation never approved, is not normal use.

This is distinct from AI01, which fires when a host *first* calls any LLM API (the LAMEHUG "malware asks a model" pattern). AI12 is about the *operating* shape of an agent framework: breadth of providers and non-sanctioned ones, not first contact. It does not try to detect the attack the agent carries out - the tools it runs (recon, BloodHound, Impacket, coercion, exfil) are caught by the behaviour rules (B01, 16, 24, 08, 14, 15, 20, CS18, B07); this catches the brain driving them.

- **Anchor:** DNS lookups of LLM providers' **API endpoints** (a program calling a model, not the browser chat sites).
- **Corroborating property, either:** the host reaches **2+ different providers** (a multi-model agent), or it reaches a **non-sanctioned** provider at all.
- **Exclusion:** your approved providers, set in the sanctioned list; a single sanctioned provider never fires.

## Query
Run hourly with a 24-hour lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "dnsrequest"
| EVAL d = TO_LOWER(COALESCE(dns.question.name, ""))
// Anchor: LLM provider API endpoints a program calls (the browser chat sites aren't here).
| WHERE d IN ("api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "router.huggingface.co",
              "api-inference.huggingface.co", "api.mistral.ai", "api.deepseek.com", "open.bigmodel.cn", "openrouter.ai",
              "api.groq.com", "api.together.xyz", "api.x.ai", "api.cohere.com", "api.cohere.ai", "api.perplexity.ai")
| EVAL provider = CASE(d == "api.openai.com", "openai", d == "api.anthropic.com", "anthropic",
                       d == "generativelanguage.googleapis.com", "google", d LIKE "*huggingface.co", "huggingface",
                       d == "api.mistral.ai", "mistral", d == "api.deepseek.com", "deepseek", d == "open.bigmodel.cn", "zhipu",
                       d == "openrouter.ai", "openrouter", d == "api.groq.com", "groq", d == "api.together.xyz", "together",
                       d == "api.x.ai", "grok", d LIKE "api.cohere.*", "cohere", d == "api.perplexity.ai", "perplexity", "other")
// Sanctioned providers your org approves (placeholders - set these to the ones you actually use, e.g. "openai", "anthropic").
| EVAL nonsanctioned = CASE(provider IN ("<sanctioned_llm_1>", "<sanctioned_llm_2>"), 0, 1)
| STATS providers = COUNT_DISTINCT(provider), provider_list = VALUES(provider), has_nonsanctioned = MAX(nonsanctioned),
        lookups = COUNT(*), process.name = VALUES(process.name), process.entity_id = MV_SLICE(VALUES(process.entity_id), 0, 9),
        host.name = VALUES(host.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id
// Agentic fingerprint. source: logic, not a measured baseline - 2+ providers = more than one model driven from one host.
| WHERE providers >= 2 OR has_nonsanctioned == 1
```

**CrowdStrike (Falcon LogScale)**, run over the last 24 hours:
```logscale
#event_simpleName=DnsRequest
// Anchor: LLM provider API endpoints a program calls (the browser chat sites aren't here).
| in(field="DomainName", ignoreCase=true, values=["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "router.huggingface.co", "api-inference.huggingface.co", "api.mistral.ai", "api.deepseek.com", "open.bigmodel.cn",
    "openrouter.ai", "api.groq.com", "api.together.xyz", "api.x.ai", "api.cohere.com", "api.cohere.ai", "api.perplexity.ai"])
| DomainName := lower(DomainName)
| case {
    DomainName=/openai\.com$/ | provider := "openai" ;
    DomainName=/anthropic\.com$/ | provider := "anthropic" ;
    DomainName=/googleapis\.com$/ | provider := "google" ;
    DomainName=/huggingface\.co$/ | provider := "huggingface" ;
    DomainName=/mistral\.ai$/ | provider := "mistral" ;
    DomainName=/deepseek\.com$/ | provider := "deepseek" ;
    DomainName=/bigmodel\.cn$/ | provider := "zhipu" ;
    DomainName=/openrouter\.ai$/ | provider := "openrouter" ;
    DomainName=/groq\.com$/ | provider := "groq" ;
    DomainName=/together\.xyz$/ | provider := "together" ;
    DomainName=/x\.ai$/ | provider := "grok" ;
    DomainName=/cohere\.(com|ai)$/ | provider := "cohere" ;
    DomainName=/perplexity\.ai$/ | provider := "perplexity" ;
    * | provider := "other" ;
  }
// Sanctioned providers your org approves (placeholders - set these to the ones you use).
| case { in(field=provider, values=["<sanctioned_llm_1>", "<sanctioned_llm_2>"]) | nonsanctioned := 0 ; * | nonsanctioned := 1 ; }
| groupBy([aid], function=[count(provider, distinct=true, as=providers), max(nonsanctioned, as=has_nonsanctioned),
    count(as=lookups), collect([ComputerName, provider, ContextProcessId]), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)], limit=max)
// Agentic fingerprint. source: logic, not a baseline - 2+ providers = more than one model from one host.
// Deliberately no * branch: this case is the threshold.
| case { test(providers >= 2) ; test(has_nonsanctioned >= 1) ; }
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
```

**Alternative source (Zscaler):** the same API endpoints in `url.domain`, grouped by `user.name` or `source.ip`. Zscaler also gives the **call volume** (DNS is cached, so FDR lookups undercount how often the agent actually calls a model), and `user_agent.original` stands in for the program (`python-requests`, `OpenAI/Python`, an SDK agent). A host looping hundreds of requests across two or more providers is the clearest agentic signal, and only the proxy sees that count.

## Before turning it on
- **Set the sanctioned list.** Put the providers your org actually uses in both placeholders (if you only approve one, leave the second as the placeholder so it never matches). An internal Azure OpenAI endpoint (`<name>.openai.azure.com`) is your own app traffic - keep it out of this rule.
- Developer and data-science hosts that legitimately use several model APIs will fire; exclude those `host.id`s and keep the rule for the rest of the estate.
- `dns.question.name` may carry a trailing dot in your index; strip it before the `IN`.

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule; a host that keeps driving models folds into the open alert.

## What it misses
- An agent that runs on the **attacker's own infrastructure** against your internet-facing services - you never see its model calls, only the attack landing on your side (that's the behaviour rules and the edge/identity detections).
- An agent restricted to a **single sanctioned provider** - breadth is the signal, so one approved model with no other tell won't fire here (AI01 catches first contact; the tempo/correlation idea catches the machine-speed action chain).

## Triage
- Name the process (LogScale: `#event_simpleName=/ProcessRollup2$/ aid=<host.id> TargetProcessId=<ContextProcessId>`). A Python or unsigned binary on a non-developer host talking to two models is the framework; a browser is a user.
- Look at what else the host did in the same window: recon, directory enumeration, lateral movement or staging (B01, 24, 16, 14, CS18). An LLM-driving process **plus** attack-tool behaviour on one host is an agentic attack in progress - isolate it.
- Check which providers (`provider_list`): a non-sanctioned or China-nexus model (DeepSeek, Zhipu, Grok) from a server is on its own worth running down.

## Test
On a lab host that has never done so, make one API call each to two different providers (e.g. `api.openai.com` and `api.deepseek.com`) - it should alert on `providers >= 2`. A single call to one non-sanctioned provider should alert on `has_nonsanctioned`.
