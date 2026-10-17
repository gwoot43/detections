# Detection ideas: C2 and tunnelling

Copies of the library's C2 and tunnelling detections, gathered in one folder. Each file is identical to its original, and an edit to either one is copied to the other.

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
| [N09](N09-zscaler-tunnel-and-policy-evasion.md) | Zscaler anonymizer, proxy-avoidance, unsanctioned VPN or DNS-over-HTTPS use | Tunnelling | `rules/06-network/N09-zscaler-tunnel-and-policy-evasion.md` |
| [W10](W10-unauthorised-rmm-or-tunnel.md) | Unapproved remote management or tunnelling tool executed | Tunnelling | `rules/03-endpoint-windows/W10-unauthorised-rmm-or-tunnel.md` |
| [Fixed 01](fixed-01-tunnel-service-connection.md) | 01 · Tunnel service connection (Zscaler) → tunnel agent detection (Zscaler + Falcon) | Tunnelling | `fixed-detections/01-tunnel-service-connection.md` |
| [Fixed 02](fixed-02-dns-tunneling.md) | 02 · DNS tunneling (Falcon DNS requests) | Tunnelling | `fixed-detections/02-dns-tunneling.md` |

## Keeping copies and originals identical
- **In Claude Code:** the hook in `.claude/settings.json` copies an edited file over its twin after every edit.
- **By hand:** `python3 tools/sync_detection_ideas.py` syncs every pair where one side has uncommitted changes. After an edit made on GitHub, pass the file you edited: `python3 tools/sync_detection_ideas.py <file>`.
- **Check:** `python3 tools/sync_detection_ideas.py --check` fails if a copy is missing or differs from its original.
- **Adding or removing a detection:** edit the list at the top of `tools/sync_detection_ideas.py`, then run it with `--readme` to create the copy and rewrite this page.
