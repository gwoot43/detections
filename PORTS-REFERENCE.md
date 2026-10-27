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

Platform is where the tool *runs* (where you'd see the process); several run from a Linux attacker box but target Windows. A 3-4 line write-up of each is in **How each tool works** below the table.

| Tool / technique | Platform | Target port(s) | Detection |
|---|---|---|---|
| **Certipy** `find` | Both | 389/636, 3268/3269; 445; 80/443 | [01], [05], [24] |
| **Certipy** `req` | Both | **445** (`\pipe\cert`), or 135 + dynamic, or 80/443 (`-web`) | [03], [01] |
| **Certipy** `auth` | Both | **88** (PKINIT, then U2U) | [04], [05] |
| **Certipy** `shadow` | Both | 389 (write key credential), 88, sometimes 464 | [02]-adjacent, AD rules |
| **Certify** (C# twin of Certipy) | Windows | 389/636, 445, 80/443 | [01], [03], [23] |
| **ADExplorer** | Windows | **389**, 636, 3268/3269 | [24], [05] |
| **AdFind / ldapdomaindump / windapsearch** | Both (AdFind: Windows) | 389, 636, 3268/3269 | [24] |
| **bloodyAD / dacledit / owneredit / pywhisker / Whisker** | Both (Whisker: Windows) | **389 / 636** | [24] (reads only); DC 4728/5136 on the write |
| **SOAPHound** | Windows | **9389 (ADWS)** | **[24]** (`directory_sweep_adws`) |
| **SharpHound / BloodHound** | Both (SharpHound: Windows; `bloodhound-python`: Linux) | 389/636, 3268/3269 (+ **9389**); **445** (IPC$); **88** | [24] (LDAP/ADWS), [08] (Kerberos/IPC$) |
| **smbclient** (Samba / `smbclient.py`) | Linux (Samba binary); Both (`smbclient.py`) | **445**, 139 | [18], [17], [23] |
| **Impacket** psexec / smbexec / atexec | Both (targets Windows) | **445** | [14], [15] |
| **Impacket** wmiexec / dcomexec | Both (targets Windows) | **135 + dynamic**, 445 | [14], [15] |
| **Impacket** secretsdump | Both (targets Windows) | 445 (remote registry); **135 + dynamic** (DCSync/DRSUAPI) | [15] (registry path) |
| **DCSync** (Mimikatz `lsadump::dcsync`, `secretsdump -just-dc`, NetExec `--ntds`) | Both (Mimikatz: Windows) | **135 + dynamic** (DRSUAPI/MS-DRSR) | DC 4662 (replication GUID); no FDR network rule yet |
| **Kerberoast / GetUserSPNs / AS-REP** | Both | **88**, 389 (find SPNs) | [04] |
| **Rubeus** | Windows | **88** | [04], [23] |
| **Kerbrute** | Both | **88** (TCP/UDP) | [23] |
| **NetExec / CrackMapExec** | Both | 445, 5985/5986, 3389, 389/636, 1433, 22, 135+dynamic | [16], [23] |
| **mssqlclient.py / PowerUpSQL** | Both (PowerUpSQL: Windows) | **1433** | [23] (name); [16] (fan-out) |
| **evil-winrm** | Both (targets Windows) | **5985 / 5986** | [23] |
| **Coercion: PetitPotam, Coercer, PrinterBug/SpoolSample, DFSCoerce** | Both (targets Windows DC) | **445** (`\pipe\lsarpc`/`efsr`/`spoolss`/`netdfs`), some 135 + dynamic | no rule yet; front of the chain [01] catches |
| **Responder** | Linux (Inveigh: Windows) | listens; poisons **UDP 5355/137/5353**, relays to 445/80/389 | (not yet a rule) |
| **mitm6** | Both | **UDP 547** (+ DNS), relays to 389/636, 445 | (not yet a rule) |
| **ntlmrelayx** | Both | relays to 445, 389/636, 80/443 (AD CS), 1433 | [01] (AD CS web leg) |
| **ligolo-ng** | Both | **11601** control (TLS); **any port** relayed to internal | [20] (bridge behaviour), [CS16] |
| **chisel / gost** | Both | operator server (443/8080/any); any port relayed | [20], [CS16], [CS18] |
| **Commercial tunnels: ngrok, cloudflared, Tailscale, ZeroTier** | Both | vendor relay ports (7844, 443, 3478, 41641…) | [CS14] (fixed vendor ports), [W10] |
| **DNS tunnelling: iodine, dnscat2, dns2tcp** | Both | **53** (UDP/TCP) | [CS03], [CS18] |
| **VS Code tunnel** | Both | **443** to Microsoft dev-tunnels | [21] |
| **IWA Direct Sockets** | Both | **any non-web port** to internal | [22] |
| **C2 beacons: Cobalt Strike, Sliver, Havoc, Mythic** | Both (CS/Havoc: Windows-focused) | 443 / 80 / **53** / 445 (SMB named-pipe beacon) | [B06] (beaconing) |
| **rclone** | Both | 443, 22 | [CS18] (name), [B07] |
| **nmap / masscan / rustscan** | Both | **any port** | [23], [16] |

## How each tool works

**Certipy** (AD CS attack tool, Python, usually a Linux attacker box). `find` binds to a DC over LDAP/GC and reads the AD CS objects to locate misconfigured templates and CAs (ESC1-ESC16), checking each CA's RPC, registry and `/certsrv/` web endpoint. `req` then requests a certificate for a target identity against a vulnerable template, by default through the CA's `cert` named pipe over SMB (also `-web` HTTP or DCOM). `auth` logs in with that certificate via Kerberos PKINIT (88) and a user-to-user request to pull the account's NT hash out of the PAC. `shadow` instead writes a key credential to a victim's `msDS-KeyCredentialLink` over LDAP and authenticates as them - no password reset. Caught across 01-05 and 24.

**Certify.** The compiled C# cousin of Certipy, run from a Windows foothold rather than a Python box. It performs the same AD CS abuse - enumerate vulnerable templates over LDAP, request a certificate from the CA, use it to authenticate. On the wire it looks the same, so 01 and 03 apply and it is also named in 23.

**ADExplorer.** A Sysinternals GUI tool that binds to a domain controller over LDAP and takes a full offline snapshot of the directory. Attackers like it because it is signed, Microsoft-published and rarely blocked, yet it pulls the same objects a BloodHound collector would. The giveaway is the LDAP read to a DC from a workstation - 24 catches the directory sweep, 05 the proxied case.

**AdFind / ldapdomaindump / windapsearch.** Command-line LDAP clients that dump users, groups, computers, trusts and ACLs from a DC - the scripted equivalent of ADExplorer, feeding the same recon. AdFind is a Windows binary; the other two are Python and cross-platform. 24 is the detection.

**bloodyAD / dacledit / owneredit / pywhisker / Whisker.** Unlike the readers above, these *write* to AD over LDAP: add a group member, edit or take ownership of a DACL, or plant a shadow-credential key. They are how a foothold becomes privilege - granting yourself DCSync rights, or adding to Domain Admins. The LDAP connection looks ordinary (24 sees the traffic); the authoritative signal is the change itself on the DC (4728/4732/5136).

**SOAPHound.** Collects the same BloodHound data as SharpHound but over AD Web Services (SOAP on 9389) instead of raw LDAP, built specifically to evade rules that only watch 389/636/3268. Because the AD PowerShell module also uses ADWS, fan-out/volume is the discriminator. 24 flags it as `directory_sweep_adws`.

**SharpHound / BloodHound.** The standard AD attack-path mapper. It reads the directory over LDAP/GC, then reaches out to every computer it found for logged-on sessions and local-admin membership, and graphs who can get to Domain Admin. That second phase is a fan-out to many hosts over SMB/IPC$ with a Kerberos ticket per host. SharpHound is Windows C#; `bloodhound-python` is the Linux collector. 24 catches the LDAP/ADWS read, 08 the Kerberos/IPC$ fan-out.

**smbclient (Samba / smbclient.py).** Samba's `smbclient` is the standard interactive SMB client on Linux - connect to a share, then `ls`/`get`/`put`. Windows needs no such binary because its kernel redirector *is* the SMB client (`net use`, Explorer, `Copy-Item`). Attackers use it to loot shares from a Linux foothold; `smbclient.py` is Impacket's cross-platform version that speaks SMB from its own stack (handy for pass-the-hash). 18 (Linux), 17 (a user process speaking SMB on Windows) and 23 cover it.

**Impacket psexec / smbexec / atexec / wmiexec / dcomexec.** The Impacket remote-exec family runs a command on a remote Windows host. psexec and smbexec install a short-lived service over SMB; atexec creates a scheduled task; wmiexec and dcomexec go through WMI/DCOM (135 + a dynamic port). All read their output back from a `__`-prefixed file on an admin share. They run from Windows or Linux but always target Windows. 14 (the `$\__` artifact) and 15 (the service installs and remote-exec pipes) catch them on the target.

**Impacket secretsdump.** Dumps credentials from a remote Windows host two ways: reading the SAM/LSA hives via the remote registry over SMB, or replicating domain hashes from a DC over DRSUAPI (DCSync). The registry path shows as remote-registry pipe access (15); the DCSync path is DC-side. Targets Windows, runs from either platform.

**DCSync** (Mimikatz `lsadump::dcsync`, `secretsdump -just-dc`, NetExec `--ntds`). Impersonates a domain controller and asks a real DC to replicate account secrets over the DRSUAPI RPC (135 + a dynamic port). With the right rights - or after a bloodyAD grant - it pulls any hash in the domain, including krbtgt for a golden ticket. There is no FDR network rule yet; the authoritative signal is DC event 4662 with the replication GUID.

**Kerberoast / GetUserSPNs / AS-REP roasting.** Requests Kerberos service tickets (TGS) for accounts that have an SPN, or AS-REP material for accounts without pre-auth, both on port 88, then cracks the returned, password-derived ciphertext offline. The SPNs are found first with an LDAP query. 04 catches the ticket requests coming from a process that isn't LSASS.

**Rubeus.** A C# Kerberos toolkit for Windows: request, renew or forge tickets, kerberoast, abuse S4U (delegation), and pass-the-ticket. It is the Windows-native counterpart to Impacket's Kerberos scripts, all port-88 traffic from a user process. 04, and named in 23.

**Kerbrute.** Sprays usernames or passwords against Kerberos pre-authentication (88, TCP/UDP). It is fast and, importantly, a *failed* guess raises no Windows logon event, so it is quieter than SMB or LDAP spraying. 23 catches it by name.

**NetExec / CrackMapExec.** The swiss-army lateral-movement tool: authenticate to many hosts at once over SMB, WinRM, RDP, LDAP or MSSQL and run modules to exec commands, dump secrets, spider shares and enumerate. The signal is the fan-out to many hosts on admin ports (16); also named in 23.

**mssqlclient.py / PowerUpSQL.** Connect to Microsoft SQL Server (1433) and abuse it: `xp_cmdshell` for command execution, linked-server hops to pivot between databases, and credential theft. PowerUpSQL is PowerShell (Windows); mssqlclient.py is cross-platform. 23 by name, 16 if it fans out.

**evil-winrm.** An interactive WinRM shell to a Windows host - PowerShell remoting over 5985/5986, with password, hash or Kerberos auth. It is the go-to once an attacker has admin credentials for a box. A Ruby tool that targets Windows; caught by name in 23.

**Coercion: PetitPotam, Coercer, PrinterBug/SpoolSample, DFSCoerce.** These call specific RPCs - MS-EFSR (`lsarpc`/`efsr`), MS-RPRN (`spoolss`) or MS-DFSNM (`netdfs`) over named pipes on 445 - to *force* a target (usually a DC) to authenticate back to the attacker. That coerced authentication is then relayed, classically to AD CS web enrolment (ESC8). No rule yet: 01 catches the relay landing on the CA, and the scoped idea is the named-pipe access on the DC (5145).

**Responder.** Answers LLMNR, NBT-NS and mDNS name-resolution broadcasts (UDP 5355/137/5353) with its own address, so a client that mistyped or failed DNS connects to the attacker instead and offers its NTLM authentication, which Responder captures or relays. Primarily a Linux tool (Inveigh is the Windows equivalent). Not yet a rule.

**mitm6.** Spoofs DHCPv6 (UDP 547) to make itself the network's IPv6 DNS server, then answers DNS to redirect victims and relays the authentication that follows (often to LDAP, for a WPAD/ADIDNS takeover). It leans on the fact that Windows prefers IPv6 and most networks don't manage it. Not yet a rule.

**ntlmrelayx.** The relay engine. It takes NTLM authentication captured by Responder/mitm6 or triggered by coercion and forwards it to another service - SMB, LDAP/LDAPS, HTTP (AD CS web enrol) or MSSQL - authenticating there as the victim. It is the payoff step of the poison/coerce chain. 01 covers the AD CS web leg.

**ligolo-ng.** A pivot/tunnel tool. The agent on a compromised host dials out to the operator's server over TLS (default 11601) and presents a userland TUN interface, so the operator routes straight into the internal network as if on-LAN. Because one process both talks to the internet and reaches many internal hosts, 20 catches it by that bridge behaviour (CS16 by rarity).

**chisel / gost.** General tunnel and SOCKS-proxy tools. A client on the compromised host connects out to an operator-run server (commonly 443 or 8080) and relays arbitrary traffic back through it - the same shape as ligolo. 20, CS16 and CS18 cover it.

**Commercial tunnels: ngrok, cloudflared, Tailscale, ZeroTier.** Legitimate remote-access and mesh agents that expose a host through the vendor's relay on fixed ports (e.g. Cloudflare 7844). Attackers abuse them as ready-made C2/ingress because the traffic looks like sanctioned SaaS and needs no inbound firewall rule. CS14 matches the fixed relay ports/domains; W10 the agent on the endpoint.

**DNS tunnelling: iodine, dnscat2, dns2tcp.** Encode command-and-control and exfiltration inside DNS queries and responses (port 53) to a domain the attacker's name server controls, so data leaves even where only DNS egresses. The signal is the volume and entropy of DNS to one domain. CS03 and CS18 cover it.

**VS Code tunnel.** `code tunnel` (Remote Tunnel Access) exposes a host through Microsoft's dev-tunnels relay over 443; whoever holds the linked GitHub/Microsoft account gets a terminal and the filesystem from vscode.dev, with no inbound rule. Because the binary is Microsoft-signed it is often allowed. 21 catches the tunnel start and its child processes.

**IWA Direct Sockets.** An Isolated Web App (a signed Chromium web bundle) can use the Direct Sockets API to open raw TCP/UDP from inside the browser - turning the browser into a port scanner, proxy or C2 client under a trusted, signed process. It is an emerging technique. 22 catches the install and the raw-socket behaviour to internal hosts.

**C2 beacons: Cobalt Strike, Sliver, Havoc, Mythic.** Implants that call back to a controller on an interval and run tasked commands, usually in memory to avoid disk. They egress over HTTPS/HTTP/DNS, and an SMB beacon talks peer-to-peer over a named pipe (445) so an internal host relays for one that can't reach the internet. Cobalt Strike and Havoc are Windows-focused; Sliver is cross-platform. B06 (beaconing cadence) is the behavioural catch.

**rclone.** A fast, legitimate file-sync utility attackers point at their own cloud or SFTP storage (443/22) to exfiltrate data in bulk, typically just before ransomware. Its presence on a server with no backup reason is the tell. CS18 by name, B07 by the mass-read-then-upload pattern.

**nmap / masscan / rustscan.** Port and host scanners that map which services are reachable across the network - the first move after a foothold. masscan and rustscan are built for speed and breadth, nmap for depth and scripting. 23 by name, 16 if the scan fans out to many internal hosts on admin ports.

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
