# New detections

Newly created detections, starting with Certipy (the AD CS attack tool, run from the attacker's own machine and usually through a SOCKS proxy on a compromised host), then ClickOnce, BloodHound collection, AWS identity checks, share hunting, Domain Admins adds, a brotli version hunt, a web-RCE post-exploitation hunt, and three lateral-movement detections (the Impacket exec output artifact, remote-exec pipes and service installs on the target, and an admin-protocol sweep). They're written for the organisation's own schema: `logs-yourorg-crowdstrike-data-default*` (FDR, `data.*` fields, lowercase `event.action`) and `logs-yourorg-microsoft-windows*` (Windows events, `winevt.event_data.*`). Replace `yourorg` and the `<placeholders>` before deploying.

## What each Certipy step leaves behind

| Step | What Certipy does | Detection |
|---|---|---|
| `find` | LDAP to a DC; on each CA, remote registry over SMB and a check of `/certsrv/` | [01](01-ntlm-client-claims-to-be-the-server.md) on the DC, [05](05-process-proxying-into-ad.md) on the pivot |
| `req` | Requests the certificate over SMB, through the `cert` pipe on the CA (or `-web`, or `-dynamic-endpoint`) | [03](03-cert-pipe-on-ca.md), [01](01-ntlm-client-claims-to-be-the-server.md) for `-web`; AD14 and I09 on the CA's own log |
| `account update -upn` | Sets a victim's UPN to the target's bare name (ESC9, ESC10) | [02](02-upn-set-without-domain.md) |
| `auth` | Kerberos logon with the certificate, then a ticket to itself for the NT hash | [04](04-kerberos-from-process-other-than-lsass.md), [05](05-process-proxying-into-ad.md) on the pivot; AD16, AD17, AD15 on the DC |
| `shadow` | Writes a key credential to the target account | I12 |
| `template`, `ca` | Edits a template (ESC4), adds an officer or enables a template (ESC7) | AD06, AD14 |

The AD and I rules are in `rules/14-ad-attack/` and `rules/05-identity/`, written for the Elastic integration's field names (`winlog.event_data.*`).

| # | Detection | Source | Catches |
|---|---|---|---|
| 01 | [NTLM client claims to be the server](01-ntlm-client-claims-to-be-the-server.md) | DC and CA 4624/4625 | Certipy's own NTLM, which names the server it's talking to as the client |
| 02 | [UPN set without a domain](02-upn-set-without-domain.md) | DC 4738 | The ESC9/ESC10 UPN swap |
| 03 | [cert pipe on the CA](03-cert-pipe-on-ca.md) | CA 5145 | `certipy req`'s default transport |
| 04 | [Kerberos from a process other than LSASS](04-kerberos-from-process-other-than-lsass.md) | Falcon | `certipy auth`, Rubeus or Impacket through a proxy on a Windows host |
| 05 | [One process proxying into AD](05-process-proxying-into-ad.md) | Falcon | Any tool reaching LDAP or Kerberos through a SOCKS proxy (also ADExplorer, ldapdomaindump) |

## Also in this folder

| # | Detection | Source | Catches |
|---|---|---|---|
| 06 | [ClickOnce chain on an endpoint](06-clickonce-app-started.md) | Falcon | A program started by ClickOnce (`dfsvc.exe` or `dfsvc.ni.exe`), started by a ClickOnce app, or run from the ClickOnce cache; investigation steps in the query |
| 07 | [ClickOnce deployment downloaded](07-clickonce-download-zscaler.md) | Zscaler | `.application` and `.deploy` downloads from sites you don't deploy from, blocked or allowed |
| 08 | [BloodHound collection sweep](08-bloodhound-collection-sweep.md) | DC 4769, target 5140 | One account reaching 50+ computers in an hour by Kerberos ticket or IPC$; Falcon pivot query names the host and process |
| 09 | [AWS identity checks](09-aws-identity-checks.md) | Falcon | `aws sts get-caller-identity` across 3+ different profiles by one user on one host within a 30-minute window (credential enumeration) |
| 10 | [Share hunting sweep](10-share-hunting-sweep.md) | Target 5140 | One account opening real shares (not `IPC$`) on 20+ computers in an hour: Snaffler, PowerView, NetExec spider, ransomware share discovery |
| 11 | [Member added to Domain Admins](11-user-added-to-domain-admins.md) | DC 4728 | Anyone added to Domain Admins, matched by the group's SID (`-512`), with an optional version for the other Tier-0 groups |
| 12 | [brotli installed versions (hunt)](12-brotli-installed-versions.md) | Falcon inventory | Where brotli is installed, grouped by upstream version with the distro build kept alongside |
| 13 | [PHP web-worker post-exploitation](13-php-web-worker-post-exploitation.md) | Falcon | Recon, shells, downloads and credential access spawned from a PHP or web-worker process (web RCE follow-on, PHP2Shell) |
| 14 | [Impacket exec output artifact](14-smb-from-user-process.md) | Falcon (target) | `cmd.exe` redirecting output to a `$\__` admin-share file: wmiexec, dcomexec, smbexec - by behaviour, not name |
| 15 | [Remote-exec pipes and service installs](15-remote-exec-pipes-and-service-installs.md) | Target 5145/4697 | A remote-exec named pipe on IPC$ (svcctl, atsvc, winreg, RemCom) or a command-shell service install: psexec, smbexec, atexec on the target |
| 16 | [Lateral sweep over admin protocols](16-lateral-sweep-admin-protocols.md) | Falcon | One process reaching 15+ internal hosts on SMB/RPC/WinRM/RDP in a short window: NetExec, CrackMapExec, PsExec loops - by fan-out, not name |
| 17 | [A user process speaking SMB](17-user-process-speaking-smb.md) | Falcon | A user-mode process (not the kernel redirector) making outbound SMB on Windows: the Impacket suite, a renamed SMB tool, `smbclient.py` - the single-connection cut 16 misses |
| 18 | [smbclient on Linux](18-smbclient-linux-share-access.md) | Falcon | Samba `smbclient` or Impacket `smbclient.py` on Linux reaching an admin share or pulling files in bulk |
| 19 | [Keylogger in script content](19-keylogger-script-content.md) | Falcon script control | A script referencing the keyboard-capture APIs (`GetAsyncKeyState`, low-level keyboard hook, raw input): PowerShell/.NET keyloggers |
| 20 | [Pivot relay: internet to internal](20-pivot-relay-internet-to-internal.md) | Falcon | One process bridging a public address and 5+ internal hosts: ligolo-ng, chisel, gost, a SOCKS proxy in a beacon - by behaviour, not name |
| 21 | [VS Code tunnel started](21-vscode-tunnel-started.md) | Falcon | `code tunnel` / Remote Tunnel Access used as C2 (ported from CS13) |
| 22 | [Isolated Web App abuse](22-isolated-web-app-abuse.md) | Falcon | An IWA installed (`.swbn`, install switches) or a browser opening raw sockets to internal hosts (Direct Sockets scanning/pivoting) |

## Before turning them on
- Field names: `winevt.logon.type`, `winevt.event_data.workstation_name`, `user_principal_name`, `target_user_name`, `subject_user_name`, `relative_target_name` and `source.ip` are guesses at your pipeline's names. Check each against an event in Discover.
- Auditing: 5145 needs "Audit Detailed File Share" on the CAs (03).
- Process names on Falcon network events: check how many arrive without one (04).

## Test
In a lab, through a SOCKS proxy on a Windows host (`proxychains` on the attacker side):
```
certipy find -u <user>@<domain> -p <password> -dc-ip <dc> -vulnerable -stdout
certipy req -u <user>@<domain> -p <password> -dc-ip <dc> -ca <ca name> -template User -target <ca host>
certipy account update -u <user>@<domain> -p <password> -dc-ip <dc> -user <victim> -upn administrator
certipy auth -pfx <user>.pfx -dc-ip <dc>
```
Expect: `find` fires 01 and 05; `req` fires 03; `account` fires 02; `auth` fires 04 and 05, and AD16 on the DC. Change the victim's UPN back afterwards.
