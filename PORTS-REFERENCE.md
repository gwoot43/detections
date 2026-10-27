# Ports and tools reference

A library-wide tuning aid for the network-based detections: which ports each red/purple-team tool targets, and which detection watches them. Use it when setting the port and CIDR filters, and to see where a tool would show up.

In the **Detection** column each id links to its rule file: a bare number (01-24) is in `certipy_detections/`, a letter-prefixed id (CS / B / W / AD …) is in `rules/`. "no rule yet" marks a gap worth building.

Private ranges throughout are `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` (internal IPv6).

## Ports, and what they're for

| Port | Proto | Service | Why an attacker hits it |
|---|---|---|---|
| 22 | TCP | SSH | lateral movement, pivoting, tunnels |
| 53 | UDP/TCP | DNS | DNS tunnelling (iodine, dnscat2, dns2tcp), C2 over DNS |
| 88 | TCP/UDP | Kerberos (AS / TGS) | auth with a cert, Kerberoasting, AS-REP roasting, ticket requests |
| 135 | TCP | RPC endpoint mapper (DCERPC) | WMI/DCOM exec, DCSync bind, service control |
| 137 / 138 | UDP | NetBIOS name / datagram | name poisoning (Responder), legacy discovery |
| 139 | TCP | NetBIOS session (legacy SMB) | SMB on old hosts |
| 389 | TCP | LDAP | directory enumeration |
| 445 | TCP | SMB | remote exec, share access, named pipes, file copy, auth coercion (`efsr`/`spoolss`/`netdfs` pipes) |
| 464 | TCP/UDP | kpasswd | password set/reset (shadow credentials, ESC resets) |
| 636 | TCP | LDAPS | directory enumeration (encrypted) |
| 1433 | TCP | MSSQL | database access, `xp_cmdshell`, relay target |
| 3268 / 3269 | TCP | Global Catalog (LDAP / LDAPS) | forest-wide directory enumeration |
| 3389 | TCP | RDP | interactive lateral movement |
| 5985 / 5986 | TCP | WinRM (HTTP / HTTPS) | remote exec (evil-winrm, NetExec) |
| 5355 / 5353 | UDP | LLMNR / mDNS | name poisoning (Responder) |
| 547 | UDP | DHCPv6 | IPv6 takeover (mitm6) |
| **9389** | TCP | **AD Web Services (ADWS)** | **directory enumeration that dodges LDAP rules (SOAPHound, AD PowerShell module)** |
| 11601 | TCP | ligolo-ng control (default, TLS) | pivot relay back to the operator |
| 49152–65535 | TCP | dynamic RPC | the port the endpoint mapper hands back for WMI/DCOM/DRSUAPI |

## Tools, their target ports, and the detection that sees them

Platform is where the tool *runs* (where you'd see the process); several run from a Linux attacker box but target Windows, noted in How it works.

| Tool / technique | Platform | How it works | Target port(s) | Detection |
|---|---|---|---|---|
| **Certipy** `find` | Both | Enumerates AD CS over LDAP for vulnerable certificate templates, then probes each CA's RPC, registry and `/certsrv/` web endpoint. | 389/636, 3268/3269; 445; 80/443 | [01], [05], [24] |
| **Certipy** `req` | Both | Requests a certificate for a target identity through the CA's `cert` RPC pipe over SMB (or the DCOM / web endpoint). | **445** (`\pipe\cert`), or 135 + dynamic, or 80/443 (`-web`) | [03], [01] |
| **Certipy** `auth` | Both | Authenticates with the issued cert via Kerberos PKINIT, then a user-to-user request to recover the account's NT hash. | **88** (PKINIT, then U2U) | [04], [05] |
| **Certipy** `shadow` | Both | Writes a key credential (`msDS-KeyCredentialLink`) onto the victim over LDAP, then logs in as them with PKINIT - no password reset needed. | 389 (write key credential), 88, sometimes 464 | [02]-adjacent, AD rules |
| **Certify** (C# twin of Certipy) | Windows | Same AD CS abuse as Certipy, compiled C# run from a Windows foothold instead of a Python box. | 389/636, 445, 80/443 | [01], [03], [23] |
| **ADExplorer** | Windows | Sysinternals GUI tool that binds to a DC over LDAP and snapshots the entire directory to an offline file. | **389**, 636, 3268/3269 | [24], [05] |
| **AdFind / ldapdomaindump / windapsearch** | Both (AdFind: Windows) | Command-line LDAP clients that dump users, groups, computers, trusts and ACLs from a DC. | 389, 636, 3268/3269 | [24] |
| **bloodyAD / dacledit / owneredit / pywhisker / Whisker** | Both (Whisker: Windows) | *Write* to AD over LDAP - add a group member, edit a DACL, take ownership, or plant a shadow-credential key. | **389 / 636** | [24] (reads only); DC 4728/5136 on the write |
| **SOAPHound** | Windows | Collects BloodHound directory data over AD Web Services (SOAP) instead of raw LDAP, to slip past LDAP-based rules. | **9389 (ADWS)** | **[24]** (`directory_sweep_adws`) |
| **SharpHound / BloodHound** | Both (SharpHound: Windows; `bloodhound-python`: Linux) | Reads the directory over LDAP, then reaches every computer for sessions and local-admins; builds the attack-path graph. | 389/636, 3268/3269 (+ **9389**); **445** (IPC$); **88** | [24] (LDAP/ADWS), [08] (Kerberos/IPC$) |
| **smbclient** (Samba / `smbclient.py`) | Linux (Samba binary); Both (`smbclient.py`) | Samba's `smbclient` is the standard SMB client on Linux - Windows needs no such binary because it speaks SMB natively through the kernel redirector (`net use`, Explorer, `Copy-Item`). Interactive: connect to a share and list/get/put files to loot it. `smbclient.py` is Impacket's cross-platform reimplementation. | **445**, 139 | [18], [17], [23] |
| **Impacket** psexec / smbexec / atexec | Both (targets Windows) | Run a command on a remote Windows host over SMB - install a short-lived service (psexec/smbexec) or scheduled task (atexec); output read back from a `__` admin-share file. | **445** | [14], [15] |
| **Impacket** wmiexec / dcomexec | Both (targets Windows) | Run a command on a remote Windows host via WMI or DCOM; the spawned `cmd.exe` writes output back over SMB. | **135 + dynamic**, 445 | [14], [15] |
| **Impacket** secretsdump | Both (targets Windows) | Dumps secrets - remote registry for SAM/LSA, or DRSUAPI replication for domain hashes (DCSync). | 445 (remote registry); **135 + dynamic** (DCSync/DRSUAPI) | [15] (registry path) |
| **DCSync** (Mimikatz `lsadump::dcsync`, `secretsdump -just-dc`, NetExec `--ntds`) | Both (Mimikatz: Windows) | Impersonates a DC and asks a real DC to replicate account secrets over DRSUAPI - pulls any hash, including krbtgt. | **135 + dynamic** (DRSUAPI/MS-DRSR) | DC 4662 (replication GUID); no FDR network rule yet |
| **Kerberoast / GetUserSPNs / AS-REP** | Both | Requests Kerberos service tickets for SPN accounts (or AS-REP for no-preauth users) and cracks them offline. | **88**, 389 (find SPNs) | [04] |
| **Rubeus** | Windows | C# Kerberos toolkit - request, renew or forge tickets, kerberoast, S4U abuse, pass-the-ticket. | **88** | [04], [23] |
| **Kerbrute** | Both | Sprays usernames/passwords against Kerberos pre-auth - fast, and failures raise no logon event. | **88** (TCP/UDP) | [23] |
| **NetExec / CrackMapExec** | Both | Swiss-army lateral tool - authenticates to many hosts over SMB/WinRM/RDP/LDAP/MSSQL and runs exec, dump and spider modules. | 445, 5985/5986, 3389, 389/636, 1433, 22, 135+dynamic | [16], [23] |
| **mssqlclient.py / PowerUpSQL** | Both (PowerUpSQL: Windows) | Connects to MSSQL and abuses it - `xp_cmdshell` for exec, linked-server hops, credential theft. | **1433** | [23] (name); [16] (fan-out) |
| **evil-winrm** | Both (targets Windows) | Interactive WinRM shell to a Windows host - PowerShell remoting over 5985/5986 with hash or Kerberos auth. | **5985 / 5986** | [23] |
| **Coercion: PetitPotam, Coercer, PrinterBug/SpoolSample, DFSCoerce** | Both (targets Windows DC) | Calls MS-EFSR / MS-RPRN / MS-DFSNM RPCs over named pipes to force a DC to authenticate to the attacker, feeding an NTLM relay (ESC8). | **445** (`\pipe\lsarpc`/`efsr`/`spoolss`/`netdfs`), some 135 + dynamic | no rule yet; front of the chain [01] catches |
| **Responder** | Linux (Inveigh: Windows) | Answers LLMNR/NBT-NS/mDNS name lookups to poison them, capturing or relaying the NTLM auth that follows. | listens; poisons **UDP 5355/137/5353**, relays to 445/80/389 | (not yet a rule) |
| **mitm6** | Both | Spoofs DHCPv6 to become the network's IPv6 DNS server, then relays the authentication it redirects. | **UDP 547** (+ DNS), relays to 389/636, 445 | (not yet a rule) |
| **ntlmrelayx** | Both | Relays captured NTLM authentication onward to SMB/LDAP/HTTP(AD CS)/MSSQL to act as the coerced victim. | relays to 445, 389/636, 80/443 (AD CS), 1433 | [01] (AD CS web leg) |
| **ligolo-ng** | Both | Agent on a compromised host dials out to the operator over TLS and relays a userland TUN interface into the internal network. | **11601** control (TLS); **any port** relayed to internal | [20] (bridge behaviour), [CS16] |
| **chisel / gost** | Both | Tunnel / SOCKS proxy - a client on the host connects out and relays arbitrary traffic back for the operator. | operator server (443/8080/any); any port relayed | [20], [CS16], [CS18] |
| **Commercial tunnels: ngrok, cloudflared, Tailscale, ZeroTier** | Both | Legitimate remote-access agents that expose a host through the vendor's relay on fixed ports - abused as C2. | vendor relay ports (7844, 443, 3478, 41641…) | [CS14] (fixed vendor ports), [W10] |
| **DNS tunnelling: iodine, dnscat2, dns2tcp** | Both | Encodes C2 and exfil traffic inside DNS queries and responses to an attacker-controlled domain. | **53** (UDP/TCP) | [CS03], [CS18] |
| **VS Code tunnel** | Both | `code tunnel` exposes a host through Microsoft's dev-tunnels relay; whoever holds the linked GitHub/MS account gets a terminal and files. | **443** to Microsoft dev-tunnels | [21] |
| **IWA Direct Sockets** | Both | An Isolated Web App uses the browser's Direct Sockets API to open raw TCP/UDP from inside Chromium - a scanner or proxy in the browser. | **any non-web port** to internal | [22] |
| **C2 beacons: Cobalt Strike, Sliver, Havoc, Mythic** | Both (CS/Havoc: Windows-focused) | Implant beacons to a controller on an interval and runs tasked commands, often in memory; SMB beacons talk over a named pipe. | 443 / 80 / **53** / 445 (SMB named-pipe beacon) | [B06] (beaconing) |
| **rclone** | Both | Fast file-sync tool pointed at attacker-controlled cloud or SFTP storage for bulk exfiltration. | 443, 22 | [CS18] (name), [B07] |
| **nmap / masscan / rustscan** | Both | Port and host scanners that map reachable services across the network. | **any port** | [23], [16] |

## The ports worth watching by behaviour, not name

- **88 from a non-`lsass` process** - Certipy `auth`, Rubeus, Kerberoasting (detection [04]).
- **389 / 636 / 3268 / 3269 / 9389 fan-out from one process** - directory collection, ADWS included (detection [24]).
- **445 from a user-mode process, or to many hosts** - Impacket/smbclient and lateral sweep ([14], [16], [17]).
- **one process bridging a public address and many internal hosts** - a pivot relay, whatever port it relays on (detection [20]).
- **9389** is the quiet one: not in the LDAP family, carries the same directory data, and is how a collector evades rules that watch only 389/636/3268. Watch it (detection [24]), but baseline first - the AD PowerShell module uses it constantly.
- **a client hitting `\pipe\efsr`/`spoolss`/`netdfs` on a DC, or a DC making an unexpected *outbound* authentication** - coercion (PetitPotam, PrinterBug), the front of the ESC8 chain [01] catches the back of. No rule yet.
- **53 to anything but your resolvers** - DNS tunnelling or C2 over DNS ([CS03]).

<!-- detection links: bare numbers -> certipy_detections/, prefixed ids -> rules/ -->
[01]: certipy_detections/01-ntlm-client-claims-to-be-the-server.md
[02]: certipy_detections/02-upn-set-without-domain.md
[03]: certipy_detections/03-cert-pipe-on-ca.md
[04]: certipy_detections/04-kerberos-from-process-other-than-lsass.md
[05]: certipy_detections/05-process-proxying-into-ad.md
[08]: certipy_detections/08-bloodhound-collection-sweep.md
[14]: certipy_detections/14-smb-from-user-process.md
[15]: certipy_detections/15-remote-exec-pipes-and-service-installs.md
[16]: certipy_detections/16-lateral-sweep-admin-protocols.md
[17]: certipy_detections/17-user-process-speaking-smb.md
[18]: certipy_detections/18-smbclient-linux-share-access.md
[20]: certipy_detections/20-pivot-relay-internet-to-internal.md
[21]: certipy_detections/21-vscode-tunnel-started.md
[22]: certipy_detections/22-isolated-web-app-abuse.md
[23]: certipy_detections/23-red-team-tools-by-name.md
[24]: certipy_detections/24-directory-enumeration-sweep.md
[CS03]: rules/07-crowdstrike-fdr/CS03-dns-tunnelling.md
[CS14]: rules/07-crowdstrike-fdr/CS14-tunnel-service-agent.md
[CS16]: rules/07-crowdstrike-fdr/CS16-rare-program-reaches-internal-admin-services.md
[CS18]: rules/07-crowdstrike-fdr/CS18-attacker-tools-by-name.md
[B06]: rules/11-behaviour/B06-c2-beaconing.md
[B07]: rules/11-behaviour/B07-mass-file-read-staging.md
[W10]: rules/03-endpoint-windows/W10-unauthorised-rmm-or-tunnel.md
