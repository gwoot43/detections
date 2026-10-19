# Detection ideas: what each one covers

Thirty-three detections for C2, tunnelling, post-exploitation and AI, grouped by what they're looking for. Each file here is identical to its original in `rules/` or `fixed-detections/`; see [README.md](README.md) for the paths and how the copies stay in sync.

## What each one covers and how

### C2: something calling home

| Rule | Covers | How it detects | How it stays quiet | Data |
|---|---|---|---|---|
| [B06](B06-c2-beaconing.md) | Any implant calling home on a schedule (Cobalt Strike, Sliver, Havoc, Mythic), over any protocol or port | The same process connects to the same external address 30+ times over an hour or more, filling most of the minutes it could | Address reached by at most 3 hosts; browsers are left to B10 | CrowdStrike network connections |
| [B10](B10-zscaler-c2-beaconing.md) | HTTP(S) C2 on fresh or uncategorised domains, including devices without Falcon | A user's traffic to one domain is present in 72+ five-minute slots across 12+ hours, 2+ requests per slot | Domain reached by at most 3 users; a browser tab drops out on the 12-hour test | Zscaler web logs (decrypted traffic) |
| [N07](N07-zscaler-c2-and-malware-callback.md) | Callbacks to infrastructure Zscaler classifies as C2, botnet, malware or cryptomining | Zscaler's own verdict, one row per device and destination, allowed versus blocked | Adware verdicts left out; critical only when a request got through | Zscaler web logs |
| [L01](L01-reverse-shell.md) | Linux reverse shells: `bash -i >& /dev/tcp`, `nc -e`, socat, Python, Perl, PHP and Ruby one-liners | The command wires a shell's input and output to a socket; the label names the shape | `/dev/tcp` counts only with a shell or stdin duplication; `ssh -i` doesn't match | CrowdStrike process starts (Linux) |

### Tunnelling: known tools and services

| Rule | Covers | How it detects | How it stays quiet | Data |
|---|---|---|---|---|
| [CS14](CS14-tunnel-service-agent.md) | Tunnel service agents: Cloudflare, ngrok, Tailscale, ZeroTier, localhost.run, serveo, pinggy, bore and a few smaller ones | The relay's fixed port (7844, 41641, 9993, 7835) or a lookup of the agent's server; the label names the service | Approved connector hosts excluded by ID | CrowdStrike connections and DNS |
| [CS13](CS13-vscode-tunnel.md) | VS Code tunnels (`code tunnel`, Remote Tunnel Access), including a renamed CLI | `tunnel` as an argument, plus the licence or service flag, the account login (`tunnel user login`), a `code*` name or a staging folder | The desktop app's `tunnel status` check excluded; approved hosts by ID | CrowdStrike process starts |
| [W10](W10-unauthorised-rmm-or-tunnel.md) | Remote-management and tunnel tools by name: AnyDesk, ScreenConnect, ngrok, chisel, frp, Tailscale and others (39 file names) | The tool runs on a host for the first time in 7 days | Ran on at most 3 hosts before, so your approved RMM drops out | CrowdStrike process starts (Windows) |
| [Fixed 01](fixed-01-tunnel-service-connection.md) | After A: tunnel agents and visits to tunnel-hosted sites at the proxy. After B: cloudflared, ngrok, chisel and `ssh`/`plink -R -D` by command shape | Agent and site domains; command-line shapes that work whatever the binary is called | Running an agent is high, visiting a tunnel-hosted site is medium | Zscaler web logs; CrowdStrike process starts |
| [N09](N09-zscaler-tunnel-and-policy-evasion.md) | Policy evasion: anonymizers, proxy avoidance, unsanctioned VPNs, Tor, DNS-over-HTTPS | Zscaler category or domain, one row per user and destination, allowed versus blocked | DoH alerts only when at most 3 users reach the resolver; blocked is low | Zscaler web logs |
| [CS03](CS03-dns-tunnelling.md) | Data or C2 carried over DNS (iodine, dnscat2, DNS beacons) | 100+ distinct names under one parent, 20+ of them with a first label of 30+ characters | Parent looked up by at most 3 hosts; mail-server blocklist lookups excluded | CrowdStrike DNS |
| [Fixed 02](fixed-02-dns-tunneling.md) | The same as CS03, on your own index | As CS03, plus 20+ TXT or NULL queries as an alternative tell | Parent looked up by at most 3 hosts; Exchange excluded | CrowdStrike DNS |

### Tunnelling: unknown tunnels and pivots, by behaviour

| Rule | Covers | How it detects | How it stays quiet | Data |
|---|---|---|---|---|
| [CS15](CS15-admin-service-reached-from-loopback.md) | Any tunnel exposing this host's own RDP or SSH, whatever it's called | RDP or SSH accepts a connection from the host itself (`127.0.0.1`, `::1`) | First time on this host in 7 days | CrowdStrike incoming connections; Windows 4624 type 10 as a second source |
| [CS16](CS16-rare-program-reaches-internal-admin-services.md) | Pivots through a tunnel or implant (chisel, ligolo-ng, frp, SOCKS in a beacon) | A program connects to RDP, SSH, SMB, RPC or WinRM on other internal hosts, new on this host | The program does this on at most 3 hosts | CrowdStrike connections |
| [L14](L14-temp-or-memory-program-listening.md) | Tunnellers, SOCKS proxies and bind shells dropped on a Linux server (BARECLAW in the BeyondTrust intrusion), including ones reached only through a local reverse proxy | A program started from `/tmp`, `/var/tmp`, `/dev/shm` or memory opens a listening port | Go's own build and test binaries excluded; real services are installed elsewhere | CrowdStrike process starts and listening sockets (Linux) |
| [CS11](CS11-rare-program-accepting-internal-connections.md) | Implant listeners, pivot servers and bind shells | A program starts accepting connections from other internal hosts, new on this host | The program does this on at most 3 hosts | CrowdStrike incoming connections |
| [CS10](CS10-web-server-new-internal-admin-connection.md) | Webshell tunnels (reGeorg, Neo-reGeorg, Suo5) and webshell lateral movement | A web server process reaches an internal admin port on a host it hasn't contacted in 7 days | Each server's own 7-day history | CrowdStrike connections |
| [CS09](CS09-windows-port-forward-portproxy.md) | Windows' built-in port forwarder (`netsh interface portproxy`) | A `netsh` command adds or changes a forward, or a write to the key forwards are stored in | One forward is the event; forwards are rare everywhere | CrowdStrike process starts and registry writes |

### Post-exploitation: covering tracks, keeping root and harvesting secrets

| Rule | Covers | How it detects | How it stays quiet | Data |
|---|---|---|---|---|
| [L07](L07-defense-evasion-log-and-history-tamper.md) | Anti-forensics in one rule: logs, login records or shell history deleted or emptied, history switched off, auditd or syslog stopped, system files re-dated | An action that destroys or re-dates (`rm`, `truncate`, `: >`, `unset HISTFILE`, `systemctl stop`, `touch -r`) on a live record: a log matched by name shape wherever it is, `wtmp`, history, the logging service. The label names the technique | The command is new on the host and run on at most 3 hosts; rotated logs don't count | CrowdStrike process starts (Linux) |
| [L13](L13-rare-setuid-root-program.md) | Setuid-root backdoors, such as a shell copied to a system-looking name (`/usr/bin/dbus-authd` in the BeyondTrust intrusion) | A program starts as root for a non-root account (effective user 0, real user not 0), new on the host | Runs setuid on at most 3 hosts, so `sudo`, `su` and `passwd` drop out | CrowdStrike process starts (Linux) |
| [L15](L15-passwordless-sudo-grant-written.md) | A `NOPASSWD` sudo rule written to give an account permanent root, including into a template that rebuilds `/etc/sudoers` | `NOPASSWD` and a sudoers path in one command, from something that writes rather than reads | The command is new on the host and run on at most 3 hosts | CrowdStrike process starts (Linux) |
| [CS17](CS17-trufflehog-secret-scan.md) | Secret harvesting with TruffleHog, as the Shai-Hulud npm worm does on every developer machine it infects | TruffleHog (by name, or a renamed copy by its own flags) scanning the file system rather than a git repository | New for that parent on the host; a security team's scheduled scan has a history; no fleet rarity, since a worm hits many hosts at once | CrowdStrike process starts (Windows, Linux, macOS) |

### Webshells at the edge

| Rule | Covers | How it detects | How it stays quiet | Data |
|---|---|---|---|---|
| [N11](N11-imperva-new-script-page-posted-by-few-clients.md) | Webshells in use (SAWFLY in the BeyondTrust intrusion), including on servers and appliances without Falcon | A script page (`.php`, `.jsp`, `.aspx`, including an encoded `%2E` dot) that first answered a POST in the last 2 hours has had 5+ successful POSTs | At most 2 clients have POSTed to it; scanners get errors, not successes | Imperva passed requests |

### AI: attacks using or aimed at AI (ATT&CK v20)

| Rule | Covers | How it detects | How it stays quiet | Data |
|---|---|---|---|---|
| [AI01](AI01-host-starts-calling-llm-api.md) | Malware that asks a public AI model what to do next (APT28's LAMEHUG), or a rogue agent | A host looks up an LLM provider's API endpoint (`api.openai.com`, `router.huggingface.co` …) for the first time in 7 days | At most 3 hosts started on that API together, so a software rollout drops out; the chat websites people use aren't on the list | CrowdStrike DNS; Zscaler as an alternative |
| [AI02](AI02-ai-coding-agent-run-unattended-with-approvals-off.md) | Malware or a poisoned project driving a local AI coding agent (Claude Code, Codex, Gemini CLI, Amazon Q, Copilot CLI), as in the s1ngularity npm compromise | The agent's approval-bypass switch plus a prompt on the command line: run unattended with nobody to say no | New for that parent and agent on the host; CI runners and orchestrators have a history | CrowdStrike process starts |
| [AI03](AI03-m365-copilot-prompt-injection-or-jailbreak.md) | Prompt injection hidden in mail, files or pages Microsoft 365 Copilot reads (EchoLeak-style), and jailbreak attempts | Copilot's own verdicts in the audit record: `XPIADetected` on content it read, `JailbreakDetected` on a prompt | Vendor verdict, so no tuning; a jailbreak alerts at medium | Purview audit (CopilotInteraction); confirm the fields are mapped |
| [AI04](AI04-azure-openai-keys-or-content-filter-new-identity.md) | LLMjacking: stolen access to your Azure OpenAI models, content filters switched off (Storm-2139) | Keys listed or regenerated, or a content filter changed, on an AI services account | New for that identity in 7 days; pipelines that read keys on every deploy have a history | Azure Activity log |
| [AI05](AI05-download-after-ai-assistant-link.md) | AI result poisoning: an assistant recommends a lookalike site and the user downloads malware from it | A user arrives at a site from an AI assistant (referrer or `utm_source` tag) and downloads a program from it | Only sites Zscaler doesn't know (unknown or newly registered); real vendors are categorised | Zscaler web logs |
| [AI06](AI06-code-editor-looks-up-rare-domain.md) | Malicious extensions in VS Code, Cursor or Windsurf calling home (GlassWorm) | The editor's own processes look up a domain new to that host | Reached by editors on at most 3 hosts; marketplace, updates, telemetry and AI assistants are everywhere | CrowdStrike DNS (LogScale joins it to the process) |
| [AI07](AI07-ai-agent-or-editor-runs-download-and-execute.md) | Poisoned `CLAUDE.md`/`SKILL.md` files, prompt-injected agents, `tasks.json` that runs on open, npm install scripts | An AI agent, code editor or `node` starts a shell whose command downloads code and runs it in one go | The command is new on the host and run on at most 3 hosts, so official installers drop out | CrowdStrike process starts |
| [AI08](AI08-prompt-for-an-ai-model-in-command-line-or-script.md) | Malware carrying prompts aimed at AI-assisted triage (MacOS.Gaslight, a 2026 Shai-Hulud variant) | Chat-template tokens or "ignore all previous instructions" in a command line or PowerShell script | Nothing a person types contains these; exclude LLM developers' hosts if needed | CrowdStrike process starts; PowerShell 4104 |
| [AI09](AI09-copilot-studio-agent-published-or-auth-changed-by-new-maker.md) | A Copilot Studio agent set up to move data out, from a compromised maker account | An agent published, or its authentication changed | New for that person in 30 days; regular makers have a history | Purview audit (Copilot Studio records); confirm the operation names |
| [AI10](AI10-defender-for-cloud-ai-threat-alerts.md) | Jailbreaks, prompt injection and data leaks against your own Azure AI apps | Defender for Cloud's AI threat-protection alerts (types starting `AI.`) passed through | Vendor verdict; resolved and false-positive alerts drop out | Defender XDR alerts; needs AI threat protection on |
| [AI11](AI11-first-large-upload-to-rarely-used-ai-app.md) | Company documents sent to an AI app nobody has assessed (shadow AI) | A user's first use of an AI app, with 5 MB or more sent | The app is used by at most 3 people; sanctioned tools are used by many | Zscaler web logs |

## Running details

| Rule | Severity | Schedule and lookback | Suppression | ATT&CK | LogScale version |
|---|---|---|---|---|---|
| B06 | High | Hourly, 3 hours | `host.id`, `process.name`, `destination.ip` / 24h | T1071.001, T1573, T1095 | Yes |
| B10 | High | Hourly, 48 hours | `user.name`, `url.domain` / 24h | T1071.001 | Not applicable (Zscaler) |
| N07 | High, critical when allowed | Every 15 min, 1 hour | `source.ip`, `destination.domain`, `severity` / 24h | T1071.001, T1105, T1571 | Not applicable |
| L01 | Critical | Per event | `host.id` / 1h | T1059.004, T1071 | Yes |
| CS14 | High | Every 15 min, 1 hour | `host.id`, `tunnel_service` / 24h | T1572, T1090.002 | Yes |
| CS13 | High | Per event | `host.id` / 24h | T1219.001, T1572 | Yes |
| W10 | High | Hourly, 7 days | `host.id`, `pname` / 24h | T1219, T1572, T1090, T1105 | Yes |
| Fixed 01 | High for agents, medium for visits | Every 15 min, 1 hour | After A: `user.name`, `service` / 24h. After B: `host.id`, `finding` / 24h | Not mapped | After B only |
| N09 | Medium, low when blocked | Every 15 min, 1 hour | `user.name`, `destination.domain`, `severity` / 24h | T1090.003, T1572, T1573 | Not applicable |
| CS03 | Medium | Every 15 min, 1 hour | `host.id`, `parent` / 24h | T1071.004, T1572, T1048.003 | Yes |
| Fixed 02 | Not set | Every 15 min, 1 hour | `host.id`, `parent` / 24h | Not mapped | Yes |
| CS15 | High | Hourly, 7 days | `host.id`, `destination.port` / 24h | T1572, T1021.001, T1021.004 | Yes |
| CS16 | High | Hourly, 7 days | `host.id`, `process.name` / 24h | T1090.001, T1572, T1021 | Yes |
| L14 | High | Every 15 min, 1 hour | `host.id`, `process.executable` / 24h | T1090.001, T1572 | Yes |
| CS11 | Medium | Hourly, 7 days | `host.id`, `pname` / 24h | T1090.001, T1572, T1571 | Yes |
| CS10 | High | Hourly, 7 days | `host.id`, `process.name` / 24h | T1090.001, T1572, T1505.003, T1021 | Yes |
| CS09 | High | Per event | `host.id` / 1h | T1090.001, T1572 | Yes |
| L07 | High | Hourly, 7 days | `host.id` / 24h | T1685.006, T1070.003, T1685.004, T1070.006 | Yes |
| L13 | High | Hourly, 7 days | `host.id` / 24h | T1548.001 | Yes |
| L15 | High | Hourly, 7 days | `host.id` / 24h | T1548.003 | Yes |
| CS17 | High | Hourly, 7 days | `host.id` / 24h | T1552.001, T1083 | Yes |
| N11 | High | Hourly, 7 days | `url.domain`, `url.path` / 24h | T1505.003, T1190 | Not applicable (Imperva) |
| AI01 | Medium | Hourly, 7 days | `host.id` / 24h | T1588.007, T1071.001 | Yes |
| AI02 | High | Hourly, 7 days | `host.id` / 24h | T1700, T1195.001, T1059 | Yes |
| AI03 | High, medium for a jailbreak | Every 15 min, 1 hour | `usr`, `finding` / 24h | T1698, T1699, T1700 | Not applicable (Microsoft 365) |
| AI04 | High for a content filter, medium for keys | Hourly, 7 days | `actor`, `action` / 24h | T1496.004, T1552 | Not applicable (Azure) |
| AI05 | High | Every 15 min, 1 hour | `user.name`, `site` / 24h | T1608.007, T1204.002 | Not applicable (Zscaler) |
| AI06 | Medium | Hourly, 7 days | `host.id` / 24h | T1195.001, T1027.018, T1071.001 | Yes (joins DNS to the process) |
| AI07 | High | Hourly, 7 days | `host.id` / 24h | T1698, T1195.001, T1105, T1059 | Yes |
| AI08 | Medium | Every 15 min, 1 hour | `host.id` / 24h | T1685.007, T1698 | Yes |
| AI09 | Medium | Hourly, 30 days | `usr`, `event.action` / 24h | T1700 | Not applicable (Microsoft 365) |
| AI10 | High | Every 15 min, 1 hour | `event.id` / 24h | T1699, T1698, T1700 | Not applicable (Defender) |
| AI11 | Medium | Hourly, 7 days | `user.name`, `zscaler_zia.web.app.name` / 24h | T1567 | Not applicable (Zscaler) |

"Per event" rules alert on each matching event; the rule's default schedule applies. The fixed detections are reworks of rules already in your environment and use your index and field names; the rest use the Elastic integration's.

## How they fit together

- **One tunnel usually trips more than one rule.** A Cloudflare tunnel exposing RDP fires CS14 (the agent) and CS15 (RDP from loopback); a chisel pivot fires W10 (if the name is unchanged) and CS16; a tunneller dropped in `/tmp` on a Linux server fires L14, and CS11 too if other hosts connect to it. Two alerts on the same `host.id` is a confirmed tunnel.
- **One intrusion trips most of the post-exploitation rules.** ARMORY CASTLE's BeyondTrust intrusion would fire N11 (the webshell in use), then L03 (the web server starting shells), L13 (the setuid shell), L15 (the sudoers backdoor), L14 (the tunneller in `/tmp`) and L07 (the log wiping), all on one host.
- **A poisoned npm package trips several at once.** A Shai-Hulud-style worm fires CS17 (its TruffleHog scan), AI07 (an install script that downloads and runs code) and AI02 (if it drives the developer's AI agent), all on the same host.
- **Endpoint and proxy see different halves.** B06 names the process and sees any protocol; B10 names the domain and URL and covers devices without Falcon.
- **Known gaps:**
  - A tool renamed to a common binary (`svchost.exe`, `powershell.exe`) blends into that name's history in CS16 and B06.
  - B10 doesn't see C2 that Zscaler can't decrypt, or C2 on categorised domains; B06 covers both from the endpoint.
  - CS14 and CS15 depend on Falcon recording UDP and loopback connections. Each rule includes a query to check.
  - L13 needs Falcon to send the real user ID (`RUID`), and N11 needs Imperva's logs of requests it let through, not only its security events. Each rule includes a query to check.
  - AI03 depends on the O365 integration indexing Copilot's audit fields, which it doesn't define; the rule has a query to check. AI02 doesn't see an agent driven through its SDK rather than its command line.
  - L07 can't see shell built-ins (`unset HISTFILE`, `history -c`) typed into an interactive shell, only ones run through `sh -c` or a script, which is how a webshell runs commands.
