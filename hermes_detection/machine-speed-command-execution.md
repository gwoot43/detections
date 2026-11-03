# Machine-speed command execution from one parent process

Unit42's account of ARTEX reports the cadence directly: bursts of **1–14 requests at about one per second, separated by regular 25–31 second pauses** — "consistent with waiting on model inference between steps, not a scanner running at a fixed rate". On an endpoint that cadence becomes commands per minute under a single parent, and the second half of the signature is what the agent reaches for: their worker agents run **nmap, nuclei, httpx, curl, ffuf** in the same session.

Two numbers, neither of them a name:

- **`per_min`** — a human at a keyboard peaks around five or six commands a minute and cannot hold it; a build script is fast but single-purpose.
- **`binaries`** — an agent spans a toolkit, a script calls one or two things, and a pipeline calls the same handful every run.

Most of the estate's automation is one binary or the same binaries every time, which is why the pair separates it better than either number alone.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// 10 minutes in the query: the measurement is per minute, so a short window carries every statistic it needs.
| WHERE @timestamp >= NOW() - 10 minutes
  AND event.action IN ("processrollup2", "syntheticprocessrollup2")
| EVAL parent = TO_LOWER(COALESCE(process.parent.name, "")),
       parent_id = TO_STRING(process.parent.entity_id),
       child = TO_LOWER(COALESCE(process.name, "")),
       minute = DATE_TRUNC(1 minute, @timestamp)
| STATS commands = COUNT(*),
        binaries = COUNT_DISTINCT(child),
        active_minutes = COUNT_DISTINCT(minute),
        children = MV_SLICE(VALUES(child), 0, 8),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, host.name, parent, parent_id
// Commands per active minute, not per elapsed minute: a session that pauses for inference still reads as
// machine speed when it works.
| EVAL per_min = ROUND(commands::double / active_minutes, 1)
// 30 commands over 3+ active minutes across 5+ distinct binaries is a starting value with no measured source
// yet - the baseline at the foot of this file is what replaces it with this estate's own numbers.
| WHERE commands >= 30 AND active_minutes >= 3 AND binaries >= 5
| SORT per_min DESC
| LIMIT 50
```

Deploy every 5 minutes over the last 10. Suppress by `host.id` + `parent` for 6h.

## Reading the alert
- **`per_min`** above 15 is a machine. Between 8 and 15 is a script or a very fast operator; below 8 is a person.
- **`children`** is the whole story: a toolkit (`nmap`, `curl`, `httpx`, `ffuf`, `nuclei`) is a scanner or an agent driving one; `vssadmin`/`ntdsutil`/`reg` is an operator working a technique; `git`/`npm`/`make` is a build.
- **`parent`** names what is driving it. `cmd.exe`/`powershell.exe`/`bash` under an interactive ancestor is a console; under a service or an agent process it is automation.
- **`active_minutes`** below 3 is excluded on purpose — a one-minute flurry is a script starting, which needs a different rule.

## Nearest benign twins
- **CI/CD runners and build agents**: high `per_min`, but the same few binaries every run and a predictable schedule. Entity pair (`host.id` + parent) once confirmed.
- **Software installers and patching**: a burst of one binary plus its children — `binaries` stays low, which is exactly the split this rule uses.
- **Vulnerability scanners** running from a managed host: high volume *and* high diversity, so they will fire. They belong in an entity pair keyed on the scanner's service account and host, not in a raised threshold — a threshold that clears them also clears the next agent.
- **A developer's loop** (`for f in *; do ...; done`): many commands, one or two binaries.

## What it misses
- **An agent that runs one long-lived process per step** rather than many short commands — an implant with its own command loop produces no process fan-out at all.
- **Commands issued inside a single interpreter** (a Python or PowerShell session calling APIs directly) — nothing new is spawned, so nothing is counted.
- **An agent running on a host with no Falcon sensor** — which the VAPOR PANDA reporting says the framework explicitly inventories for.
- **The inference pause itself.** The 25–31 second regularity is the most distinctive part of Unit42's report, but a per-event rule cannot see gaps: expressing it needs the interval distribution between consecutive events of one session, which this pipeline does not expose as a window function. Saying it plainly is better than approximating it with a threshold that means something else.

## Baseline
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 7 days
  AND event.action == "processrollup2"
| EVAL parent = TO_LOWER(COALESCE(process.parent.name, "")),
       child = TO_LOWER(COALESCE(process.name, "")),
       minute = DATE_TRUNC(1 minute, @timestamp)
| STATS commands = COUNT(*), binaries = COUNT_DISTINCT(child), active_minutes = COUNT_DISTINCT(minute)
    BY host.id, parent, minute
| EVAL per_min = ROUND(commands::double / active_minutes, 1)
// this is the baseline: no threshold, because filtering first would hide the sessions it exists to measure.
// It is the source for the 30 / 3 / 5 starting values in the rule above.
| STATS sessions = COUNT(*), p99_commands = PERCENTILE(commands, 99), p99_binaries = PERCENTILE(binaries, 99),
        max_commands = MAX(commands), max_binaries = MAX(binaries)
    BY parent
| SORT max_commands DESC
| LIMIT 40
```
The parents at the top are the estate's own automation — read their `max_binaries` before tuning: a build agent sits at 2-4 binaries no matter how fast it runs, which is the gap this rule lives in.

## A cheap companion hunt
Unit42 lists self-describing user agents on the agent's traffic — `"Mozilla/5.0 (security-testing; authorized)"`, `"…recon-audit"` — alongside `ffuf`, `nuclei` and `httpx` in one session. Those strings rotate, so this is a hunt rather than a rule, but it catches a host used as a scanner from inside the estate:
```esql
FROM logs-zscaler_zia.web-*
| WHERE @timestamp >= NOW() - 15 minutes
| EVAL ua = TO_LOWER(COALESCE(user_agent.original, ""))
| WHERE ua LIKE "*ffuf*" OR ua LIKE "*nuclei*" OR ua LIKE "*httpx*"
     OR ua LIKE "*security-testing*" OR ua LIKE "*recon-audit*" OR ua LIKE "*sqlmap*"
| STATS requests = COUNT(*), domains = COUNT_DISTINCT(url.domain)
    BY ua, host.name
// 20 requests from one user agent in a quarter hour: this is a hunt, so the number only trims browser noise
// rather than separating a scanner from its benign twin - the baseline for it is the estate's own UA spread
| WHERE requests >= 20
| SORT requests DESC
| LIMIT 50
```

## References
- Unit42, *Activity using ARTEX agentic AI framework* (30 Oct 2026) - the 1-14 request bursts at about one per second, the 25-31 second inference pauses, and the toolset (nmap, nuclei, httpx, curl, ffuf): `github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-10-30-activity-using-ARTEX-agentic-AI.txt`
- MITRE T1059 (command and scripting interpreter), T1595.002 (vulnerability scanning), T1685.007-adjacent agentic execution
