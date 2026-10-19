# Detection ideas: C2, tunnelling, post-exploitation and AI

Copies of the library's C2, tunnelling, post-exploitation and AI detections, gathered in one folder. Each file is identical to its original, and an edit to either one is copied to the other.

[SUMMARY.md](SUMMARY.md) says what each one covers, how it detects and how it stays quiet, with severity, schedule, suppression and ATT&CK.

| File | Detection | Group | Original |
|---|---|---|---|
| [B06](B06-c2-beaconing.md) | C2 beaconing - catches Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel by behaviour | C2 | `rules/11-behaviour/B06-c2-beaconing.md` |
| [B10](B10-zscaler-c2-beaconing.md) | Steady beaconing to an uncategorised or newly registered domain, by at most three users (Zscaler) | C2 | `rules/11-behaviour/B10-zscaler-c2-beaconing.md` |
| [N07](N07-zscaler-c2-and-malware-callback.md) | Zscaler C2, malware callback or known-bad category from an endpoint, allowed or blocked | C2 | `rules/06-network/N07-zscaler-c2-and-malware-callback.md` |
| [L01](L01-reverse-shell.md) | Reverse shell launched | C2 | `rules/04-endpoint-linux/L01-reverse-shell.md` |
| [CS03](CS03-dns-tunnelling.md) | DNS tunnelling - many long, distinct names under one parent domain from one host | Tunnelling | `rules/07-crowdstrike-fdr/CS03-dns-tunnelling.md` |
| [CS09](CS09-windows-port-forward-portproxy.md) | Windows port forward created with netsh portproxy (traffic relayed through this host) | Tunnelling | `rules/07-crowdstrike-fdr/CS09-windows-port-forward-portproxy.md` |
| [CS10](CS10-web-server-new-internal-admin-connection.md) | Web server process connects to internal RDP, SMB, SSH, WinRM or RPC on a host it has never contacted (webshell tunnel or pivot) | Tunnelling | `rules/07-crowdstrike-fdr/CS10-web-server-new-internal-admin-connection.md` |
| [CS11](CS11-rare-program-accepting-internal-connections.md) | Program starts accepting connections from other internal hosts, new on this host and rare in the fleet (implant listener or pivot) | Tunnelling | `rules/07-crowdstrike-fdr/CS11-rare-program-accepting-internal-connections.md` |
| [CS13](CS13-vscode-tunnel.md) | VS Code tunnel started on an endpoint (code tunnel, Remote Tunnel Access) | Tunnelling | `rules/07-crowdstrike-fdr/CS13-vscode-tunnel.md` |
| [CS14](CS14-tunnel-service-agent.md) | Tunnel service agent running on an endpoint (Cloudflare, ngrok, Tailscale, ZeroTier, SSH tunnel services, bore and others) | Tunnelling | `rules/07-crowdstrike-fdr/CS14-tunnel-service-agent.md` |
| [CS15](CS15-admin-service-reached-from-loopback.md) | RDP or SSH reached from the host itself (traffic relayed in by a tunnel, whatever it's called) | Tunnelling | `rules/07-crowdstrike-fdr/CS15-admin-service-reached-from-loopback.md` |
| [CS16](CS16-rare-program-reaches-internal-admin-services.md) | Rare program connects to RDP, SSH, SMB or WinRM on other internal hosts (pivot through a tunnel or implant) | Tunnelling | `rules/07-crowdstrike-fdr/CS16-rare-program-reaches-internal-admin-services.md` |
| [L14](L14-temp-or-memory-program-listening.md) | Program started from a temp folder or memory opens a listening port (tunneller, proxy or bind shell) | Tunnelling | `rules/04-endpoint-linux/L14-temp-or-memory-program-listening.md` |
| [N09](N09-zscaler-tunnel-and-policy-evasion.md) | Zscaler anonymizer, proxy-avoidance, unsanctioned VPN or DNS-over-HTTPS use | Tunnelling | `rules/06-network/N09-zscaler-tunnel-and-policy-evasion.md` |
| [W10](W10-unauthorised-rmm-or-tunnel.md) | Unapproved remote management or tunnelling tool executed | Tunnelling | `rules/03-endpoint-windows/W10-unauthorised-rmm-or-tunnel.md` |
| [Fixed 01](fixed-01-tunnel-service-connection.md) | 01 · Tunnel service connection (Zscaler) → tunnel agent detection (Zscaler + Falcon) | Tunnelling | `fixed-detections/01-tunnel-service-connection.md` |
| [Fixed 02](fixed-02-dns-tunneling.md) | 02 · DNS tunneling (Falcon DNS requests) | Tunnelling | `fixed-detections/02-dns-tunneling.md` |
| [L07](L07-defense-evasion-log-and-history-tamper.md) | Linux anti-forensics - logs, login records or shell history deleted or emptied, logging stopped, or system files re-dated | Post-exploitation | `rules/04-endpoint-linux/L07-defense-evasion-log-and-history-tamper.md` |
| [L13](L13-rare-setuid-root-program.md) | Rare program runs setuid root (SUID backdoor such as a copied shell) | Post-exploitation | `rules/04-endpoint-linux/L13-rare-setuid-root-program.md` |
| [L15](L15-passwordless-sudo-grant-written.md) | Passwordless sudo grant written to a sudoers file from the command line | Post-exploitation | `rules/04-endpoint-linux/L15-passwordless-sudo-grant-written.md` |
| [CS17](CS17-trufflehog-secret-scan.md) | One process tests credentials against several unrelated online services within minutes (secret scanner such as TruffleHog, or a stealer) | Post-exploitation | `rules/07-crowdstrike-fdr/CS17-trufflehog-secret-scan.md` |
| [N11](N11-imperva-new-script-page-posted-by-few-clients.md) | New script page answering POSTs from one or two clients at the Imperva edge (webshell in use) | Webshell | `rules/06-network/N11-imperva-new-script-page-posted-by-few-clients.md` |
| [AI01](AI01-host-starts-calling-llm-api.md) | Host starts calling a public LLM API directly (malware or an agent using an AI model at runtime) | AI | `rules/17-ai-detections/AI01-host-starts-calling-llm-api.md` |
| [AI02](AI02-ai-coding-agent-run-unattended-with-approvals-off.md) | AI coding agent run unattended with every approval switched off (malware or a poisoned project driving a local agent) | AI | `rules/17-ai-detections/AI02-ai-coding-agent-run-unattended-with-approvals-off.md` |
| [AI03](AI03-m365-copilot-prompt-injection-or-jailbreak.md) | Microsoft 365 Copilot detects a prompt injection in content it read, or a jailbreak in a prompt | AI | `rules/17-ai-detections/AI03-m365-copilot-prompt-injection-or-jailbreak.md` |
| [AI04](AI04-azure-openai-keys-or-content-filter-new-identity.md) | Azure OpenAI keys listed or content filter changed by an identity new to it (LLMjacking) | AI | `rules/17-ai-detections/AI04-azure-openai-keys-or-content-filter-new-identity.md` |
| [AI05](AI05-download-after-ai-assistant-link.md) | Program downloaded from an unknown site that an AI assistant sent the user to (AI result poisoning) | AI | `rules/17-ai-detections/AI05-download-after-ai-assistant-link.md` |
| [AI06](AI06-code-editor-looks-up-rare-domain.md) | VS Code or an AI code editor looks up a domain few other installs reach (malicious extension calling home) | AI | `rules/17-ai-detections/AI06-code-editor-looks-up-rare-domain.md` |
| [AI07](AI07-ai-agent-or-editor-runs-download-and-execute.md) | AI coding agent or code editor runs a command that downloads code and executes it (poisoned instructions, project files or packages) | AI | `rules/17-ai-detections/AI07-ai-agent-or-editor-runs-download-and-execute.md` |
| [AI08](AI08-prompt-for-an-ai-model-in-command-line-or-script.md) | Text written for an AI model in a command line or PowerShell script (prompt injection against AI-assisted triage) | AI | `rules/17-ai-detections/AI08-prompt-for-an-ai-model-in-command-line-or-script.md` |
| [AI09](AI09-copilot-studio-agent-published-or-auth-changed-by-new-maker.md) | Copilot Studio agent published or its authentication changed by someone new to it | AI | `rules/17-ai-detections/AI09-copilot-studio-agent-published-or-auth-changed-by-new-maker.md` |
| [AI10](AI10-defender-for-cloud-ai-threat-alerts.md) | Defender for Cloud alert on your own AI apps (jailbreak, prompt injection, data leak through a model) | AI | `rules/17-ai-detections/AI10-defender-for-cloud-ai-threat-alerts.md` |
| [AI11](AI11-first-large-upload-to-rarely-used-ai-app.md) | First large upload by a user to an AI app few people in the organisation use (data sent to shadow AI) | AI | `rules/17-ai-detections/AI11-first-large-upload-to-rarely-used-ai-app.md` |

## Keeping copies and originals identical
- **In Claude Code:** the hook in `.claude/settings.json` copies an edited file over its twin after every edit.
- **By hand:** `python3 tools/sync_detection_ideas.py` syncs every pair where one side has uncommitted changes. After an edit made on GitHub, pass the file you edited: `python3 tools/sync_detection_ideas.py <file>`.
- **Check:** `python3 tools/sync_detection_ideas.py --check` fails if a copy is missing or differs from its original.
- **Adding or removing a detection:** edit the list at the top of `tools/sync_detection_ideas.py`, then run it with `--readme` to create the copy and rewrite this page.
