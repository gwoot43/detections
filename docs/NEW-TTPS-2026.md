# New TTPs and MITRE additions to build for (as of 2026-09)

This is the answer to "any new attack TTPs in the last couple of months, and new MITRE additions?" It maps recent tradecraft to the rules in this library and flags gaps to add next.

## MITRE ATT&CK framework changes you should reflect

### ATT&CK v19 (released 2026-04-28)
- **Defense Evasion split into two tactics.** Defense Evasion is retired as a single tactic. It is now **Stealth (TA0005)** — obfuscation, execution guardrails, process injection, indicator removal — and **Defense Impairment (TA0112)** — disabling firewalls, killing EDR, modifying defensive infrastructure. Action: when you tag rules and build your coverage matrix, split the old Defense Evasion column. Our W05 (EDR tamper), CS01 (BYOVD) and L07 (log tamper) map to Defense Impairment; W03/W04 obfuscated execution and CS06 injection map to Stealth.
- **New AI-enabled and social-engineering techniques** were added (see the T168x range below), reflecting adversary use of and attacks on AI systems.
- Enterprise now stands at 15 tactics, 222 techniques, 475 sub-techniques.

### New Enterprise techniques worth tracking (v18 Oct 2025 and v19 Apr 2026)
- **T1677 Poisoned Pipeline Execution** — CI/CD abuse. Gap in this library (we have no CI/CD source). Add if you onboard build-system logs.
- **T1679 Selective Exclusion** — ransomware skipping .dll/.exe/system files so the host still boots to show the ransom note. Relevant to L10/X05 tuning.
- **T1680 Local Storage Discovery** — mapping drives/volumes/hypervisors before impact. Relates to W09/host recon.
- **T1681 Search Threat Vendor Data** — adversaries monitoring reporting about their own campaigns and rotating infrastructure within days. Threat-intel process concern, not a log rule.
- **T1682 Query Public AI Services**, **T1683 Generate Content**, **T1684 Social Engineering (as a technique)**, **T1685 Disable or Modify Tools** (now with sub-techniques for cloud logs, event logs, tool UI spoofing). T1685 is directly relevant to W05/E10/C09.
- Note: verify the exact IDs/names against your ATT&CK Navigator import before hard-coding them in dashboards; the T168x numbering above is from v19 release reporting.

### MITRE ATLAS
For anything involving your own AI/LLM systems, use **MITRE ATLAS** (AI-specific, v2026.09) rather than ATT&CK. Out of scope for these five domains but flag it if you deploy internal AI agents.

## Recent tradecraft (last few months) and where it is covered

### Device code phishing and OAuth token theft — COVERED (I08, C05, C11, X02)
STORM-2372 through 2025, then **EvilTokens** and **ConsentFix v3** phishing-as-a-service in 2026 automate device-code capture and token exchange. No password, no MFA prompt, survives password reset. This is arguably the top identity threat right now. Our device-code rule (I08), consent rule (C05), your CA-bypass rule (C11) and the fan-out correlation (X02) cover it. Make sure token/session **revocation**, not just password reset, is in the playbook.

### ClickFix / FileFix / CrashFix — COVERED (W03)
ClickFix (fake CAPTCHA / "paste to verify") was ~47% of initial access in Microsoft's 2025 reporting. **FileFix** (2025) uses the Explorer address bar; **CrashFix** (Feb 2026) uses a browser-crash lure; **FileFix 2.0** adds a mark-of-the-web bypass via browser "Save As". W03 covers the execution artefact; add the RunMRU/TypedPaths registry angle (noted in W03 and CS02) for the forensic side.

### BYOVD EDR killers — COVERED (CS01, W05, X05)
As of early 2026, 54+ EDR-killer tools abuse 35+ signed drivers; RansomHub, BlackByte, Akira and Scattered Spider all use BYOVD. **Reynolds** ransomware (Feb 2026) bundles the vulnerable driver in the payload and blinds Falcon/Cortex/Sophos in seconds. CS01 (driver load) plus W05 (tamper) plus X05 (precursor chain) is the coverage. Keep the loldrivers.io hash list fresh via a scheduled import.

### Supply-chain worms (Shai-Hulud family) — PARTIAL GAP
NCC Group tracked **Mini Shai-Hulud, Miasma and Hades** through mid-2026 (npm/package-ecosystem self-propagating credential stealers). If you have developer endpoints and CI, add detections for package post-install scripts touching credentials and for `npm`/`pip` spawning network tools. L02/L05 catch some on Linux build hosts; a dedicated dev-endpoint rule set is a follow-up.

### Identity attacks via deepfake / help-desk social engineering — PARTIAL
Scattered Spider-style help-desk resets and MFA fatigue remain prominent; deepfake-assisted voice is now repeatable at volume. I10 (MFA method registered), I05 (MFA fatigue via spray), and W10 (RMM dropped after a help-desk call) cover the technical residue. The human process (help-desk verification) is a control, not a detection.

## Gaps to schedule next
1. **CI/CD pipeline** detections (T1677) — needs build-system logs onboarded.
2. **Developer endpoint / package-manager** supply-chain rules (Shai-Hulud class).
3. **SaaS / Cloud App** detections beyond Entra (Defender for Cloud Apps / MDA) if licensed — mass download, OAuth app anomaly, SharePoint/OneDrive exfil.
4. **AI system monitoring** (ATLAS) if you deploy internal LLM agents.
5. Re-tag the whole library to the **v19 Stealth / Defense Impairment** split when you import into ATT&CK Navigator.
