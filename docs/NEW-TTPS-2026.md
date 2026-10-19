# New TTPs and MITRE additions to build for (as of 2026-10)

This is the answer to "any new attack TTPs in the last couple of months, and new MITRE additions?" It maps recent tradecraft to the rules in this library and flags gaps to add next.

## MITRE ATT&CK framework changes you should reflect

### ATT&CK v19 (released 2026-04-28)
- **Defense Evasion split into two tactics.** Defense Evasion is retired as a single tactic. It is now **Stealth (TA0005)** — obfuscation, execution guardrails, process injection, indicator removal — and **Defense Impairment (TA0112)** — disabling firewalls, killing EDR, modifying defensive infrastructure. Action: when you tag rules and build your coverage matrix, split the old Defense Evasion column. Our W05 (EDR tamper), CS01 (BYOVD) and L07 (log tamper) map to Defense Impairment; W03/W04 obfuscated execution and CS06 injection map to Stealth.
- **New AI-enabled and social-engineering techniques** were added (see the T168x range below), reflecting adversary use of and attacks on AI systems.
- Enterprise now stands at 15 tactics, 222 techniques, 475 sub-techniques.

### ATT&CK v20 (released 2026-10-13)
Nine new Enterprise techniques, five of them about AI. The library is now tagged against v20.
- **T1698 Indirect Prompt Injection** and **T1699 Direct Prompt Injection** (Execution): instructions hidden in content an AI reads, or typed straight at it. Covered for Microsoft 365 Copilot by AI03, for your own Azure AI apps by AI10, and for coding agents by AI07.
- **T1700 AI-Enabled Exfiltration**: steering an enterprise AI agent into sending data out. Covered by AI03 (Copilot) and AI02 (local coding agents driven by malware).
- **T1608.007 AI Result Poisoning** (Resource Development): planting web content so AI assistants recommend the attacker's site or download. Happens outside your network; AI05 catches the download that follows.
- **T1685.007 Impair Autonomous Defenses**: prompts embedded in malware to derail LLM-assisted analysis. Only relevant if you use an LLM to triage; AI08.
- **T1696 Anti-Automation Evasion** (CAPTCHA solving and avoidance), **T1697 Steal Application Specific Passwords**: not AI-specific; not yet covered.
- **T1195.001** now includes IDE and coding-agent configuration files (`tasks.json`, `SKILL.md`). AI02 covers an agent being driven, AI07 what poisoned files make an agent or editor run, AI06 malicious extensions.

### New Enterprise techniques worth tracking (v18 Oct 2025 and v19 Apr 2026)
- **T1677 Poisoned Pipeline Execution** — CI/CD abuse. Gap in this library (we have no CI/CD source). Add if you onboard build-system logs.
- **T1679 Selective Exclusion** — ransomware skipping .dll/.exe/system files so the host still boots to show the ransom note. Relevant to L10/X05 tuning.
- **T1680 Local Storage Discovery** — mapping drives/volumes/hypervisors before impact. Relates to B09 (host and domain recon burst).
- **T1681 Search Threat Vendor Data** — adversaries monitoring reporting about their own campaigns and rotating infrastructure within days. Threat-intel process concern, not a log rule.
- **T1682 Query Public AI Services**, **T1683 Generate Content**, **T1684 Social Engineering (as a technique)**, **T1685 Disable or Modify Tools** (now with sub-techniques for cloud logs, event logs, tool UI spoofing). T1685 is directly relevant to W05/E10/C09.
- Note: verify the exact IDs/names against your ATT&CK Navigator import before hard-coding them in dashboards; the T168x numbering above is from v19 release reporting.

### MITRE ATLAS
For anything involving your own AI/LLM systems, use **MITRE ATLAS** (AI-specific, v2026.09) rather than ATT&CK. Out of scope for these five domains but flag it if you deploy internal AI agents.

## Recent tradecraft (last few months) and where it is covered

### Device code phishing and OAuth token theft — COVERED (C11, C05, X02)
STORM-2372 through 2025, then **EvilTokens** and **ConsentFix v3** phishing-as-a-service in 2026 automate device-code capture and token exchange. No password, no MFA prompt, survives password reset. This is arguably the top identity threat right now. Our device-code and CA-bypass rule (C11), consent rule (C05) and the fan-out correlation (X02, which includes device registration after a device-code sign-in) cover it. Make sure token/session **revocation**, not just password reset, is in the playbook.

### ClickFix / FileFix / CrashFix — COVERED (W03)
ClickFix (fake CAPTCHA / "paste to verify") was ~47% of initial access in Microsoft's 2025 reporting. **FileFix** (2025) uses the Explorer address bar; **CrashFix** (Feb 2026) uses a browser-crash lure; **FileFix 2.0** adds a mark-of-the-web bypass via browser "Save As". W03 covers the execution artefact; add the RunMRU/TypedPaths registry angle (noted in W03 and CS02) for the forensic side.

### BYOVD EDR killers — COVERED (CS01, W05, X05)
As of early 2026, 54+ EDR-killer tools abuse 35+ signed drivers; RansomHub, BlackByte, Akira and Scattered Spider all use BYOVD. **Reynolds** ransomware (Feb 2026) bundles the vulnerable driver in the payload and blinds Falcon/Cortex/Sophos in seconds. CS01 (driver load) plus W05 (tamper) plus X05 (precursor chain) is the coverage. Keep the loldrivers.io hash list fresh via a scheduled import.

### Supply-chain worms (Shai-Hulud family) — PARTIAL GAP
NCC Group tracked **Mini Shai-Hulud, Miasma and Hades** through mid-2026 (npm/package-ecosystem self-propagating credential stealers). If you have developer endpoints and CI, add detections for package post-install scripts touching credentials and for `npm`/`pip` spawning network tools. L02/L05 catch some on Linux build hosts; a dedicated dev-endpoint rule set is a follow-up.

### Identity attacks via deepfake / help-desk social engineering — PARTIAL
Scattered Spider-style help-desk resets and MFA fatigue remain prominent; deepfake-assisted voice is now repeatable at volume. I10 (MFA method registered), S12 (MFA fatigue), and W10 (RMM dropped after a help-desk call) cover the technical residue. The human process (help-desk verification) is a control, not a detection.

## AI-related attacks: rules and ideas to investigate

**Rules in the library** (`rules/17-ai-detections/`). Each names its source; confirm the "Check before deploying" items before enabling.

| Rule | Detects | Source |
|---|---|---|
| AI01 | A host starts calling a public LLM API directly (malware asking a model for commands, as APT28's LAMEHUG does) | CrowdStrike DNS; Zscaler as an alternative |
| AI02 | An AI coding agent run unattended with every approval off (malware driving local agents, as in the s1ngularity npm compromise) | CrowdStrike process starts |
| AI03 | Microsoft 365 Copilot flags a prompt injection in content it read, or a jailbreak in a prompt | Purview audit (CopilotInteraction) via the O365 integration |
| AI04 | Azure OpenAI keys listed or content filter changed by an identity new to it (LLMjacking) | Azure Activity log |
| AI05 | A program downloaded from an unknown site an AI assistant sent the user to (AI result poisoning, T1608.007) | Zscaler web logs |
| AI06 | VS Code, Cursor or Windsurf looks up a domain few other installs reach (malicious extensions such as GlassWorm, T1195.001, T1027.018) | CrowdStrike DNS (LogScale joins it to the process) |
| AI07 | An AI coding agent or code editor runs a download-and-execute command (poisoned `CLAUDE.md`/`SKILL.md`, `tasks.json` that runs on open, npm install scripts) | CrowdStrike process starts |
| AI08 | Text written for an AI model in a command line or PowerShell script (attacks on AI-assisted triage, T1685.007) | CrowdStrike process starts; PowerShell 4104 |
| AI09 | A Copilot Studio agent published, or its authentication changed, by someone new to it (T1700) | Purview audit (Copilot Studio records) |
| AI10 | Defender for Cloud alerts on your own Azure AI apps: jailbreaks, prompt injection, data leaks (T1699) | Defender XDR alerts |
| AI11 | A user's first large upload to an AI app few people in the organisation use (shadow AI) | Zscaler web logs |

**Not detectable from your logs:**
- T1682, T1683 and T1588.007: researching targets, generating lures and obtaining AI access happen outside your network.
- T1684 and T1683.002, AI voice and help-desk social engineering: covered by what follows (S11, S12, I10).

## Gaps to schedule next
1. **CI/CD pipeline** detections (T1677) — needs build-system logs onboarded.
2. **Developer endpoint / package-manager** supply-chain rules (Shai-Hulud class). AI02 and AI07 cover malware driving local AI agents and install scripts that download and run code; CS17 covers the worm's TruffleHog secret scan.
3. **SaaS / Cloud App** detections beyond Entra (Defender for Cloud Apps / MDA) if licensed — mass download, OAuth app anomaly, SharePoint/OneDrive exfil.
4. **AI system monitoring**: `rules/17-ai-detections` (AI01-AI11). Use MITRE ATLAS as well if you deploy your own LLM agents.
5. The library is tagged against **ATT&CK v20**; re-import `docs/attack-navigator-layer.json` into ATT&CK Navigator after each regeneration.
