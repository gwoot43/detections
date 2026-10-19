---
id: AI02
name: AI coding agent run unattended with every approval switched off (malware or a poisoned project driving a local agent)
category: ai
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1700, T1195.001, T1059]
data_source: CrowdStrike FDR ProcessRollup2 (Windows, Linux, macOS)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
AI coding agents (Claude Code, Codex, Gemini CLI, Amazon Q, GitHub Copilot CLI) can read every file a developer can and run any command, but by default they ask before acting. Malware has learned to drive them. In the 2025 Nx compromise (s1ngularity), a poisoned npm package started each agent it found with its approvals switched off and a prompt telling it to find wallets, keys and tokens, then sent the results to GitHub. ATT&CK v20 calls this AI-Enabled Exfiltration (T1700), and has added coding-agent instruction files to T1195.001.

What gives it away is the combination. A developer working with an agent types at it in a terminal. A program driving one passes its instructions on the command line and switches every approval off, because nobody is there to click yes.

- **Anchor:** an agent's switch that turns off every approval: `--dangerously-skip-permissions` or `bypassPermissions` (Claude Code), `--dangerously-bypass-approvals-and-sandbox` (Codex), `--yolo` or `--approval-mode yolo` (Gemini CLI, Codex), `--trust-all-tools` (Amazon Q), `--allow-all-tools` (GitHub Copilot CLI).
- **Corroborating property:** it runs unattended, with its instructions on the command line (`-p`, `--print`, `--prompt`, `exec`, `--no-interactive`).
- **Exclusion by newness:** this host hasn't had the same parent start the same agent this way in 7 days. CI runners and agent orchestrators do it daily and have a history. There is no fleet-wide rarity test, because a poisoned package lands on many developer machines at once.

The agent's command line holds the prompt, so the alert shows what it was told to do.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Anchor: an AI coding agent's switch that turns off every approval. The LIKEs are cheap (indexed); the RLIKE below makes them exact.
| WHERE event.action IN ("ProcessRollup2", "SyntheticProcessRollup2")
  AND (process.command_line LIKE "*dangerously*" OR process.command_line LIKE "*yolo*" OR process.command_line LIKE "*ypassPermissions*"
       OR process.command_line LIKE "*trust-all-tools*" OR process.command_line LIKE "*allow-all-tools*")
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE cmd RLIKE """.*(--dangerously-skip-permissions|bypasspermissions|--dangerously-bypass-approvals-and-sandbox|--yolo|approval-mode[ =]yolo|--trust-all-tools|--allow-all-tools)([ \"'].*)?"""
  // Corroborating property: run unattended, with its instructions on the command line instead of typed by a person.
  AND cmd RLIKE """.* (-p|--print|--prompt|exec|--no-interactive)([ \"'=].*)?"""
// Claude Code installed through npm runs as node, so the pairing below is keyed on the parent and the program as they appear.
| EVAL process.name = TO_LOWER(process.name), process.parent.name = TO_LOWER(COALESCE(process.parent.name, "unknown"))
// One row per host, parent and agent: when this pairing first ran unattended in the 7 days.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), runs = COUNT(*), process.command_line = VALUES(process.command_line),
        process.executable = VALUES(process.executable), user.name = VALUES(user.name), process.entity_id = VALUES(process.entity_id),
        host.name = VALUES(host.name)
    BY host.id, process.parent.name, process.name
// New on this host in the last 2 hours. CI runners and agent orchestrators do this daily and have a history.
| WHERE first_seen >= NOW() - 2 hours
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
// Anchor: an AI coding agent's switch that turns off every approval.
| CommandLine=/--dangerously-skip-permissions|bypasspermissions|--dangerously-bypass-approvals-and-sandbox|--yolo|approval-mode[ =]yolo|--trust-all-tools|--allow-all-tools/i
// Corroborating property: run unattended, with its instructions on the command line.
| CommandLine=/ (-p|--print|--prompt|exec|--no-interactive)([ "'=]|$)/i
| parent := lower(ParentBaseFileName)
| default(field=parent, value="unknown", replaceEmpty=true)
| program := lower(FileName)
// One row per host, parent and agent: when this pairing first ran unattended in the 7 days.
| groupBy([aid, parent, program], function=[min(@timestamp, as=first_seen), count(as=runs), collect([ComputerName, UserName, CommandLine])],
          limit=max)
// New on this host in the last 2 hours.
| _now := now()
| test(first_seen > _now - 7200000)
```

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and a host alerts once, when it starts.

## Known false positives / exclusions
- A developer's own script or a new agent orchestrator that runs an agent headless with approvals off. It alerts once for that host and parent, then has a history. That's still a risky setup worth knowing about: anything that can edit the script or the repository it works in can steer the agent.
- A new CI runner. It alerts at its first job, then has a history. If you build runners often, exclude them by `host.id`.

## Blind spot
A program that drives the agent through its SDK or a local API rather than starting the CLI doesn't show here. Nor does an agent started interactively by a developer who has been tricked by a poisoned project file (`CLAUDE.md`, `AGENTS.md`, `SKILL.md`). There the developer's approvals are the defence, unless approvals are off by default in their settings.

## Triage
- Read the prompt in `process.command_line`. Instructions to search for keys, tokens, wallets, `.env` files or SSH keys, or to inventory the file system, are the s1ngularity pattern.
- Look at the parent. A package manager's script (`node` under `npm`, `python` under `pip`), a file in a temp folder or a project's `node_modules` is malware. Find the package that started it and when it was installed.
- See what the agent did: its child processes and the files it wrote. Then look for the exfiltration: a new public repository under the developer's GitHub account, or uploads to a web service. Rotate every credential on the host.

## Test
On a lab host with Claude Code installed, run it from a Python script rather than a terminal: `python -c "import subprocess; subprocess.run(['claude', '--dangerously-skip-permissions', '-p', 'list the files in this folder'])"`. It should alert within the hour, with `python` as the parent and the prompt in the command line.
