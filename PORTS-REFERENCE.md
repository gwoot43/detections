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

| Tool / technique | Target port(s) | Doing what | Detection |
|---|---|---|---|
| **Certipy** `find` | 389/636, 3268/3269; 445; 80/443 | enumerate templates + CAs | [01], [05], [24] |
| **Certipy** `req` | **445** (`\pipe\cert`), or 135 + dynamic, or 80/443 (`-web`) | request the certificate | [03], [01] |
| **Certipy** `auth` | **88** (PKINIT, then U2U) | logon with the cert for the NT hash | [04], [05] |
| **Certipy** `shadow` | 389 (write key credential), 88, sometimes 464 | key-credential persistence | [02]-adjacent, AD rules |
| **Certify** (C# AD CS, Windows twin of Certipy) | 389/636, 445, 80/443 | find / request vulnerable templates | [01], [03], [23] |
| **ADExplorer** | **389**, 636, 3268/3269 | browse / snapshot the directory | [24], [05] |
| **AdFind / ldapdomaindump / windapsearch** | 389, 636, 3268/3269 | directory enumeration | [24] |
| **bloodyAD / dacledit / owneredit / pywhisker / Whisker** | **389 / 636** | DACL abuse & shadow-credential *writes* (add to a group, grant rights, write a key credential) | [24] (reads only); DC 4728/5136 on the write |
| **SOAPHound** | **9389 (ADWS)** | directory enumeration, LDAP-rule evasion | **[24]** (`directory_sweep_adws`) |
| **SharpHound / BloodHound** | 389/636, 3268/3269 (+ **9389**); **445** (IPC$); **88** | directory + session/local-admin collection | [24] (LDAP/ADWS), [08] (Kerberos/IPC$) |
| **smbclient** (Samba / `smbclient.py`) | **445**, 139 | share access, file pull | [18], [17], [23] |
| **Impacket** psexec / smbexec / atexec | **445** | service/task/pipe over IPC$ | [14], [15] |
| **Impacket** wmiexec / dcomexec | **135 + dynamic**, 445 | WMI/DCOM exec, read output over SMB | [14], [15] |
| **Impacket** secretsdump | 445 (remote registry); **135 + dynamic** (DCSync/DRSUAPI) | hash/secret dump | [15] (registry path) |
| **DCSync** (Mimikatz `lsadump::dcsync`, `secretsdump -just-dc`, NetExec `--ntds`) | **135 + dynamic** (DRSUAPI/MS-DRSR) | replicate every hash from the DC | DC 4662 (replication GUID); no FDR network rule yet |
| **Kerberoast / GetUserSPNs / AS-REP** | **88**, 389 (find SPNs) | request roastable tickets | [04] |
| **Rubeus** | **88** | asktgt / asktgs / kerberoast / s4u / pass-the-ticket | [04], [23] |
| **Kerbrute** | **88** (TCP/UDP) | username enum, password spray | [23] |
| **NetExec / CrackMapExec** | 445, 5985/5986, 3389, 389/636, 1433, 22, 135+dynamic | multi-protocol lateral movement | [16], [23] |
| **mssqlclient.py / PowerUpSQL** | **1433** | MSSQL access, `xp_cmdshell`, relay target | [23] (name); [16] (fan-out) |
| **evil-winrm** | **5985 / 5986** | remote shell | [23] |
| **Coercion: PetitPotam, Coercer, PrinterBug/SpoolSample, DFSCoerce** | **445** (`\pipe\lsarpc`/`efsr`/`spoolss`/`netdfs`), some 135 + dynamic | force a DC/host to authenticate → relayed to AD CS (ESC8) or LDAP | no rule yet; front of the chain [01] catches |
| **Responder** | listens; poisons **UDP 5355/137/5353**, relays to 445/80/389 | name poisoning + relay | (not yet a rule) |
| **mitm6** | **UDP 547** (+ DNS), relays to 389/636, 445 | IPv6 takeover + relay | (not yet a rule) |
| **ntlmrelayx** | relays to 445, 389/636, 80/443 (AD CS), 1433 | NTLM relay | [01] (AD CS web leg) |
| **ligolo-ng** | **11601** control (TLS); **any port** relayed to internal | pivot relay | [20] (bridge behaviour), [CS16] |
| **chisel / gost** | operator server (443/8080/any); any port relayed | pivot relay | [20], [CS16], [CS18] |
| **Commercial tunnels: ngrok, cloudflared, Tailscale, ZeroTier** | vendor relay ports (7844, 443, 3478, 41641…) | remote access / C2 | [CS14] (fixed vendor ports), [W10] |
| **DNS tunnelling: iodine, dnscat2, dns2tcp** | **53** (UDP/TCP) | C2 / exfil over DNS | [CS03], [CS18] |
| **VS Code tunnel** | **443** to Microsoft dev-tunnels | remote access / C2 | [21] |
| **IWA Direct Sockets** | **any non-web port** to internal | scan / pivot from the browser | [22] |
| **C2 beacons: Cobalt Strike, Sliver, Havoc, Mythic** | 443 / 80 / **53** / 445 (SMB named-pipe beacon) | implant traffic (port-agnostic) | [B06] (beaconing) |
| **rclone** | 443, 22 | cloud / SFTP exfiltration | [CS18] (name), [B07] |
| **nmap / masscan / rustscan** | **any port** | scanning | [23], [16] |

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
