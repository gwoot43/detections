# Ports and tools reference

A tuning aid for the network-based detections in this folder: which ports each tool targets, and which detection watches them. Use it when setting the port and CIDR filters, and to see where a tool would show up.

Private ranges throughout are `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` (internal IPv6).

## Ports, and what they're for

| Port | Proto | Service | Why an attacker hits it |
|---|---|---|---|
| 22 | TCP | SSH | lateral movement, pivoting, tunnels |
| 88 | TCP/UDP | Kerberos (AS / TGS) | auth with a cert, Kerberoasting, AS-REP roasting, ticket requests |
| 135 | TCP | RPC endpoint mapper (DCERPC) | WMI/DCOM exec, DCSync bind, service control |
| 137 / 138 | UDP | NetBIOS name / datagram | name poisoning (Responder), legacy discovery |
| 139 | TCP | NetBIOS session (legacy SMB) | SMB on old hosts |
| 389 | TCP | LDAP | directory enumeration |
| 445 | TCP | SMB | remote exec, share access, named pipes, file copy |
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
| **Certipy** `find` | 389/636, 3268/3269; 445; 80/443 | enumerate templates + CAs | 01, 05, 24 |
| **Certipy** `req` | **445** (`\pipe\cert`), or 135 + dynamic, or 80/443 (`-web`) | request the certificate | 03, 01 |
| **Certipy** `auth` | **88** (PKINIT, then U2U) | logon with the cert for the NT hash | 04, 05 |
| **Certipy** `shadow` | 389 (write key credential), 88, sometimes 464 | key-credential persistence | 02-adjacent, AD rules |
| **ADExplorer** | **389**, 636, 3268/3269 | browse / snapshot the directory | 24, 05 |
| **AdFind / ldapdomaindump / windapsearch** | 389, 636, 3268/3269 | directory enumeration | 24 |
| **SOAPHound** | **9389 (ADWS)** | directory enumeration, LDAP-rule evasion | **24** (`directory_sweep_adws`) |
| **SharpHound / BloodHound** | 389/636, 3268/3269 (+ **9389**); **445** (IPC$); **88** | directory + session/local-admin collection | 24 (LDAP/ADWS), 08 (Kerberos/IPC$) |
| **smbclient** (Samba / `smbclient.py`) | **445**, 139 | share access, file pull | 18, 17, 23 |
| **Impacket** psexec / smbexec / atexec | **445** | service/task/pipe over IPC$ | 14, 15 |
| **Impacket** wmiexec / dcomexec | **135 + dynamic**, 445 | WMI/DCOM exec, read output over SMB | 14, 15 |
| **Impacket** secretsdump | 445 (remote registry); **135 + dynamic** (DCSync/DRSUAPI) | hash/secret dump | 15 (registry path) |
| **Kerberoast / GetUserSPNs / AS-REP** | **88**, 389 (find SPNs) | request roastable tickets | 04 |
| **Kerbrute** | **88** (TCP/UDP) | username enum, password spray | 23 |
| **NetExec / CrackMapExec** | 445, 5985/5986, 3389, 389/636, 1433, 22, 135+dynamic | multi-protocol lateral movement | 16, 23 |
| **evil-winrm** | **5985 / 5986** | remote shell | 23 |
| **Responder** | listens; poisons **UDP 5355/137/5353**, relays to 445/80/389 | name poisoning + relay | (not yet a rule) |
| **mitm6** | **UDP 547** (+ DNS), relays to 389/636, 445 | IPv6 takeover + relay | (not yet a rule) |
| **ntlmrelayx** | relays to 445, 389/636, 80/443 (AD CS), 1433 | NTLM relay | 01 (AD CS web leg) |
| **ligolo-ng** | **11601** control (TLS); **any port** relayed to internal | pivot relay | 20 (bridge behaviour), CS16 |
| **chisel / gost** | operator server (443/8080/any); any port relayed | pivot relay | 20, CS16, CS18 |
| **VS Code tunnel** | **443** to Microsoft dev-tunnels | remote access / C2 | 21 |
| **IWA Direct Sockets** | **any non-web port** to internal | scan / pivot from the browser | 22 |
| **nmap / masscan / rustscan** | **any port** | scanning | 23, 16 |

## The ports worth watching by behaviour, not name

- **88 from a non-`lsass` process** - Certipy `auth`, Rubeus, Kerberoasting (detection 04).
- **389 / 636 / 3268 / 3269 / 9389 fan-out from one process** - directory collection, ADWS included (detection 24).
- **445 from a user-mode process, or to many hosts** - Impacket/smbclient and lateral sweep (14, 16, 17).
- **one process bridging a public address and many internal hosts** - a pivot relay, whatever port it relays on (detection 20).
- **9389** is the quiet one: not in the LDAP family, carries the same directory data, and is how a collector evades rules that watch only 389/636/3268. Watch it (detection 24), but baseline first - the AD PowerShell module uses it constantly.
