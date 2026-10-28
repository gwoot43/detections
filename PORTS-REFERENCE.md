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

Platform is where the tool *runs* (where you'd see the process); several run from a Linux attacker box but target Windows. How it works is a short mechanism note; Port(s) is the destination it hits; Detection links the rule that sees it.

| Tool / technique | Platform | How it works | Target port(s) | Detection |
|---|---|---|---|---|
| **Certipy** `find` | Both | Enumeration step. Binds to a DC over LDAP/GC and reads the AD CS objects to find misconfigured templates and CAs (ESC1-16), checking each CA's RPC, registry and `/certsrv/` web endpoint. Usually run from a Linux box and exported for BloodHound. | 389/636, 3268/3269; 445; 80/443 | [01], [05], [24] |
| **Certipy** `req` | Both | Requests a certificate for a target identity against a vulnerable template - by default through the CA's `cert` named pipe over SMB, or `-web` HTTP(S) enrolment, or DCOM via the RPC mapper. This is the exploitation step of most ESC paths. | **445** (`\pipe\cert`), or 135 + dynamic, or 80/443 (`-web`) | [03], [01] |
| **Certipy** `auth` | Both | Takes the issued certificate and logs in as the target via Kerberos PKINIT (88), then a user-to-user request to pull the account's NT hash out of the PAC. The result is the victim's credentials without their password. | **88** (PKINIT, then U2U) | [04], [05] |
| **Certipy** `shadow` | Both | Abuses write access by adding a key credential to a victim's `msDS-KeyCredentialLink` over LDAP, then authenticating as them with PKINIT - no password reset, and the attribute can be cleaned afterwards. The shadow-credentials technique. | 389 (write key credential), 88, sometimes 464 | [02]-adjacent, AD rules |
| **Certify** (C# twin of Certipy) | Windows | The compiled C# cousin of Certipy, run from a Windows foothold. Same AD CS abuse - enumerate vulnerable templates over LDAP, request a cert from the CA, authenticate with it - so it looks the same on the wire. | 389/636, 445, 80/443 | [01], [03], [23] |
| **ADExplorer** | Windows | Sysinternals GUI tool that binds to a DC over LDAP and snapshots the whole directory offline. Attackers like it because it is signed and rarely blocked, yet pulls the same objects a BloodHound collector would. | **389**, 636, 3268/3269 | [24], [05] |
| **AdFind / ldapdomaindump / windapsearch** | Both (AdFind: Windows) | Command-line LDAP clients that dump users, groups, computers, trusts and ACLs from a DC - the scripted equivalent of ADExplorer, feeding the same recon. AdFind is a Windows binary; the other two are Python. | 389, 636, 3268/3269 | [24] |
| **bloodyAD / dacledit / owneredit / pywhisker / Whisker** | Both (Whisker: Windows) | Unlike the readers, these *write* to AD over LDAP - add a group member, edit or take ownership of a DACL, or plant a shadow-credential key. They turn a foothold into privilege (self-granting DCSync rights, adding to Domain Admins). The LDAP traffic looks ordinary; the change on the DC is the real signal. | **389 / 636** | [24] (reads only); DC 4728/5136 on the write |
| **SOAPHound** | Windows | Collects the same BloodHound data as SharpHound but over AD Web Services (SOAP on 9389) instead of raw LDAP, built to evade rules that watch only 389/636/3268. The AD PowerShell module also uses ADWS, so fan-out is the discriminator. | **9389 (ADWS)** | **[24]** (`directory_sweep_adws`) |
| **SharpHound / BloodHound** | Both (SharpHound: Windows; `bloodhound-python`: Linux) | The standard AD attack-path mapper. Reads the directory over LDAP/GC, then reaches every computer it found for sessions and local-admin membership, graphing who can reach Domain Admin. That second phase fans out to many hosts over SMB/IPC$ with a Kerberos ticket each. | 389/636, 3268/3269 (+ **9389**); **445** (IPC$); **88** | [24] (LDAP/ADWS), [08] (Kerberos/IPC$) |
| **smbclient** (Samba / `smbclient.py`) | Linux (Samba binary); Both (`smbclient.py`) | Samba's `smbclient` is the standard Linux SMB client - connect to a share, then list/get/put files. Windows needs no such binary because its kernel redirector *is* the SMB client (`net use`, Explorer). Attackers loot shares with it from a Linux foothold; `smbclient.py` is Impacket's cross-platform version that speaks SMB from its own stack. | **445**, 139 | [18], [17], [23] |
| **Impacket** psexec / smbexec / atexec | Both (targets Windows) | Run a command on a remote Windows host over SMB - psexec/smbexec install a short-lived service, atexec creates a scheduled task. All read output back from a `__`-prefixed file on an admin share. Runs from either platform, always targets Windows. | **445** | [14], [15] |
| **Impacket** wmiexec / dcomexec | Both (targets Windows) | Run a command on a remote Windows host via WMI or DCOM (135 + a dynamic port) rather than a service. The spawned `cmd.exe` writes its output back over SMB to the same `__` admin-share file. | **135 + dynamic**, 445 | [14], [15] |
| **Impacket** secretsdump | Both (targets Windows) | Dumps credentials from a remote Windows host - reading the SAM/LSA hives via the remote registry over SMB, or replicating domain hashes from a DC over DRSUAPI (DCSync). The registry path shows as remote-registry pipe access. | 445 (remote registry); **135 + dynamic** (DCSync/DRSUAPI) | [15] (registry path) |
| **DCSync** (Mimikatz `lsadump::dcsync`, `secretsdump -just-dc`, NetExec `--ntds`) | Both (Mimikatz: Windows) | Impersonates a DC and asks a real DC to replicate account secrets over the DRSUAPI RPC (135 + dynamic). With the right rights it pulls any hash, including krbtgt for a golden ticket. The authoritative signal is DC event 4662 with the replication GUID. | **135 + dynamic** (DRSUAPI/MS-DRSR) | DC 4662 (replication GUID); no FDR network rule yet |
| **Kerberoast / GetUserSPNs / AS-REP** | Both | Requests Kerberos service tickets for SPN accounts (or AS-REP material for no-preauth accounts) on port 88, then cracks the password-derived ciphertext offline. SPNs are found first with an LDAP query. | **88**, 389 (find SPNs) | [04] |
| **Rubeus** | Windows | A C# Kerberos toolkit for Windows - request, renew or forge tickets, kerberoast, abuse S4U delegation, pass-the-ticket. The Windows-native counterpart to Impacket's Kerberos scripts, all port-88 traffic from a user process. | **88** | [04], [23] |
| **Kerbrute** | Both | Sprays usernames or passwords against Kerberos pre-authentication (88, TCP/UDP). Fast, and a failed guess raises no Windows logon event, so it is quieter than SMB or LDAP spraying. | **88** (TCP/UDP) | [23] |
| **NetExec / CrackMapExec** | Both | The swiss-army lateral tool - authenticate to many hosts at once over SMB/WinRM/RDP/LDAP/MSSQL and run modules to exec, dump secrets, spider shares and enumerate. The signal is the fan-out to many hosts on admin ports. | 445, 5985/5986, 3389, 389/636, 1433, 22, 135+dynamic | [16], [23] |
| **mssqlclient.py / PowerUpSQL** | Both (PowerUpSQL: Windows) | Connect to MSSQL (1433) and abuse it - `xp_cmdshell` for execution, linked-server hops to pivot between databases, credential theft. PowerUpSQL is PowerShell (Windows); mssqlclient.py is cross-platform. | **1433** | [23] (name); [16] (fan-out) |
| **evil-winrm** | Both (targets Windows) | An interactive WinRM shell to a Windows host - PowerShell remoting over 5985/5986 with password, hash or Kerberos auth. The go-to once an attacker has admin credentials for a box. | **5985 / 5986** | [23] |
| **Coercion: PetitPotam, Coercer, PrinterBug/SpoolSample, DFSCoerce** | Both (targets Windows DC) | Call specific RPCs - MS-EFSR (`lsarpc`/`efsr`), MS-RPRN (`spoolss`) or MS-DFSNM (`netdfs`) over named pipes on 445 - to *force* a target (usually a DC) to authenticate back to the attacker. That coerced auth is then relayed, classically to AD CS web enrolment (ESC8). | **445** (`\pipe\lsarpc`/`efsr`/`spoolss`/`netdfs`), some 135 + dynamic | no rule yet; front of the chain [01] catches |
| **Responder** | Linux (Inveigh: Windows) | Answers LLMNR/NBT-NS/mDNS broadcasts (UDP 5355/137/5353) with its own address, so a client that failed DNS connects to the attacker and offers its NTLM auth, which it captures or relays. Primarily Linux (Inveigh is the Windows equivalent). | listens; poisons **UDP 5355/137/5353**, relays to 445/80/389 | (not yet a rule) |
| **mitm6** | Both | Spoofs DHCPv6 (UDP 547) to become the network's IPv6 DNS server, then answers DNS to redirect victims and relays the authentication that follows (often to LDAP for a WPAD/ADIDNS takeover). Leans on Windows preferring IPv6. | **UDP 547** (+ DNS), relays to 389/636, 445 | (not yet a rule) |
| **ntlmrelayx** | Both | The relay engine - takes NTLM auth captured by Responder/mitm6 or triggered by coercion and forwards it to SMB/LDAP/HTTP(AD CS)/MSSQL, authenticating there as the victim. The payoff step of the poison/coerce chain. | relays to 445, 389/636, 80/443 (AD CS), 1433 | [01] (AD CS web leg) |
| **ligolo-ng** | Both | A pivot tool. The agent on a compromised host dials out to the operator over TLS (default 11601) and presents a userland TUN, so the operator routes straight into the internal network. One process both reaches the internet and many internal hosts. | **11601** control (TLS); **any port** relayed to internal | [20] (bridge behaviour), [CS16] |
| **chisel / gost** | Both | General tunnel/SOCKS-proxy tools - a client on the host connects out to an operator server (commonly 443 or 8080) and relays arbitrary traffic back. Same internet-to-internal bridge shape as ligolo. | operator server (443/8080/any); any port relayed | [20], [CS16], [CS18] |
| **Commercial tunnels: ngrok, cloudflared, Tailscale, ZeroTier** | Both | Legitimate remote-access/mesh agents that expose a host through the vendor's relay on fixed ports (e.g. Cloudflare 7844). Abused as ready-made C2/ingress because the traffic looks like sanctioned SaaS and needs no inbound rule. | vendor relay ports (7844, 443, 3478, 41641…) | [CS14] (fixed vendor ports), [W10] |
| **DNS tunnelling: iodine, dnscat2, dns2tcp** | Both | Encode C2 and exfil traffic inside DNS queries and responses (53) to a domain the attacker's name server controls, so data leaves even where only DNS egresses. The signal is DNS volume/entropy to one domain. | **53** (UDP/TCP) | [CS03], [CS18] |
| **VS Code tunnel** | Both | `code tunnel` exposes a host through Microsoft's dev-tunnels relay over 443; whoever holds the linked GitHub/MS account gets a terminal and files from vscode.dev. Microsoft-signed, so often allowed. | **443** to Microsoft dev-tunnels | [21] |
| **IWA Direct Sockets** | Both | An Isolated Web App (a signed Chromium web bundle) uses the Direct Sockets API to open raw TCP/UDP from inside the browser - a port scanner, proxy or C2 under a trusted signed process. An emerging technique. | **any non-web port** to internal | [22] |
| **C2 beacons: Cobalt Strike, Sliver, Havoc, Mythic** | Both (CS/Havoc: Windows-focused) | Implants that call back to a controller on an interval and run tasked commands, usually in memory. They egress over HTTPS/HTTP/DNS; an SMB beacon talks peer-to-peer over a named pipe (445) so an internal host relays for one with no internet. | 443 / 80 / **53** / 445 (SMB named-pipe beacon) | [B06] (beaconing) |
| **rclone** | Both | A fast, legitimate file-sync utility pointed at attacker cloud/SFTP storage (443/22) to exfiltrate in bulk, typically just before ransomware. Its presence on a server with no backup reason is the tell. | 443, 22 | [CS18] (name), [B07] |
| **nmap / masscan / rustscan** | Both | Port and host scanners that map which services are reachable - the first move after a foothold. masscan/rustscan for speed and breadth, nmap for depth and scripting. | **any port** | [23], [16] |

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
