# New TTPs and MITRE additions to build for (as of 2026-10)

This is the answer to "any new attack TTPs in the last couple of months, and new MITRE additions?" It maps recent tradecraft to the rules in this library and flags gaps to add next.

## MITRE ATT&CK framework changes you should reflect

### ATT&CK v19 (released 2026-04-28)
- **Defense Evasion split into two tactics.** Defense Evasion is retired as a single tactic. It is now **Stealth (TA0005)** — obfuscation, execution guardrails, process injection, indicator removal — and **Defense Impairment (TA0112)** — disabling firewalls, killing EDR, modifying defensive infrastructure. Action: when you tag rules and build your coverage matrix, split the old Defense Evasion column. Our W05 (EDR tamper), CS01 (BYOVD) and L07 (log tamper) map to Defense Impairment; W03/W04 obfuscated execution and CS06 injection map to Stealth.
- **New AI-enabled and social-engineering techniques** were added (see the T168x range below), reflecting adversary use of and attacks on AI systems.
- Enterprise now stands at 15 tactics, 222 techniques, 475 sub-techniques.

### ATT&CK v20 (released 2026-10-13)
Nine new Enterprise techniques, five of them about AI. The library is now tagged against v20.
- **T1698 Indirect Prompt Injection** and **T1699 Direct Prompt Injection** (Execution): instructions hidden in content an AI reads, or typed straight at it. Covered for Microsoft 365 Copilot by C13.
- **T1700 AI-Enabled Exfiltration**: steering an enterprise AI agent into sending data out. Covered by C13 (Copilot) and CS18 (local coding agents driven by malware).
- **T1608.007 AI Result Poisoning** (Resource Development): planting web content so AI assistants recommend the attacker's site or download. Happens outside your network; see the ideas below for the download that follows.
- **T1685.007 Impair Autonomous Defenses**: prompts embedded in malware to derail LLM-assisted analysis. Only relevant if you use an LLM to triage; see the ideas below.
- **T1696 Anti-Automation Evasion** (CAPTCHA solving and avoidance), **T1697 Steal Application Specific Passwords**: not AI-specific; not yet covered.
- **T1195.001** now includes IDE and coding-agent configuration files (`tasks.json`, `SKILL.md`). CS18 covers an agent being driven; see the ideas below for files that run on open.

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

**Rules in the library:**

| Rule | Detects | Source |
|---|---|---|
| CS17 | A host starts calling a public LLM API directly (malware asking a model for commands, as APT28's LAMEHUG does) | CrowdStrike DNS; Zscaler as an alternative |
| CS18 | An AI coding agent run unattended with every approval off (malware driving local agents, as in the s1ngularity npm compromise) | CrowdStrike process starts |
| C13 | Microsoft 365 Copilot flags a prompt injection in content it read, or a jailbreak in a prompt | Purview audit (CopilotInteraction) via the O365 integration |
| C14 | Azure OpenAI keys listed or content filter changed by an identity new to it (LLMjacking) | Azure Activity log |

**Ideas to investigate.** These aren't built yet, because each depends on a source or field that needs confirming first.

| Technique | Idea | Likely source | Check first |
|---|---|---|---|
| T1608.007 AI Result Poisoning | An executable or installer downloaded from an uncategorised or newly registered domain right after an AI assistant linked to it (`utm_source=chatgpt.com` in the URL, or a referrer of `chatgpt.com`, `perplexity.ai`, `copilot.microsoft.com`, `gemini.google.com`) | Zscaler web logs | Whether your Zscaler logs keep the referrer, the query string and the downloaded file type |
| T1195.001, T1027.018 (GlassWorm-style malicious VS Code extensions) | VS Code looking up a domain few other VS Code installs reach | CrowdStrike DNS joined to the process (LogScale) | The VS Code rare-DNS query being tuned now |
| T1195.001 (project files that run on open) | VS Code starting a shell that downloads or runs code within a minute of a folder opening, with no build started (`tasks.json` with `runOn: folderOpen`, used by Contagious Interview) | CrowdStrike process starts (parent `Code.exe`) | What VS Code's normal children look like in your data (git, node, language servers) |
| T1685.007 Impair Autonomous Defenses | Command lines or PowerShell script blocks containing chat-template tokens (`<\|im_start\|>`, `<\|system\|>`, `[INST]`) or "ignore previous instructions" | CrowdStrike command lines; Windows PowerShell 4104 | Only matters if you use an LLM to triage (Charlotte AI, Elastic AI Assistant); whether you collect 4104 |
| T1700 (SaaS agents) | A Copilot Studio agent published or changed with a connector that sends data outside (HTTP request, external email, custom connector) | Purview audit (Copilot Studio / Power Platform records) | Whether you use Copilot Studio, and whether those records reach `logs-o365.audit-*` |
| T1699 against your own AI apps | Prompt Shields jailbreak verdicts on your Azure OpenAI apps | Azure OpenAI diagnostic logs | Whether you host LLM apps and send their diagnostics to Elastic |
| Exfiltration to AI apps | First large upload by a user to an unsanctioned generative-AI app | Zscaler (generative-AI cloud app category, upload bytes) | Which Zscaler field carries the AI app category; N08 already covers large uploads in general |
| T1684, T1683.002 (AI voice and help-desk social engineering) | Already covered by what follows: S11 (help-desk MFA reset then new-location sign-in), S12, I10 | Entra | Nothing |
| T1682, T1683, T1588.007 | Researching targets, generating lures and obtaining AI access happen outside your network | None | Nothing to log |

## Gaps to schedule next
1. **CI/CD pipeline** detections (T1677) — needs build-system logs onboarded.
2. **Developer endpoint / package-manager** supply-chain rules (Shai-Hulud class). CS18 covers malware driving local AI agents; package install scripts touching credentials are still open.
3. **SaaS / Cloud App** detections beyond Entra (Defender for Cloud Apps / MDA) if licensed — mass download, OAuth app anomaly, SharePoint/OneDrive exfil.
4. **AI system monitoring**: C13 and C14 cover Copilot and Azure OpenAI. Use MITRE ATLAS if you deploy your own LLM agents, and work through the ideas table above.
5. The library is tagged against **ATT&CK v20**; re-import `docs/attack-navigator-layer.json` into ATT&CK Navigator after each regeneration.
