# Implement: detections chosen to build next

Copies of the detections picked to build next, gathered in one folder. Each file is identical to its original, and an edit to either one is copied to the other.

AD CS is kept to the three highest-fidelity rules, all on data already collected (DC logs and FDR), in priority order: AD16 (a certificate logon then a ticket to itself: certipy auth pulling the NT hash), AD17 (the DC refusing a certificate that belongs to another account or can't be tied to one) and AD03 (the CA's private key backed up: a golden certificate). AD15 (first certificate logon) is broader but fires on new smartcard users; AD14 (ESC7) needs the CA's own Security log. Both stay in the library.

| File | Detection | Group | Original |
|---|---|---|---|
| [CS17](CS17-trufflehog-secret-scan.md) | Secret scanner on a host - one process tests keys against several unrelated providers (TruffleHog, Shai-Hulud, stealers) | Secrets | `rules/07-crowdstrike-fdr/CS17-trufflehog-secret-scan.md` |
| [AD16](AD16-pkinit-then-ticket-to-self-unpac-the-hash.md) | Certificate logon followed by a ticket to itself (UnPAC-the-hash - Certipy auth, Rubeus /getcredentials) | AD CS, priority 1 | `rules/14-ad-attack/AD16-pkinit-then-ticket-to-self-unpac-the-hash.md` |
| [AD17](AD17-kdc-certificate-mapping-failure.md) | Domain controller refused a certificate logon - certificate belongs to another account, has no strong mapping, or predates the account (Kdcsvc 39, 40, 41) | AD CS, priority 2 | `rules/14-ad-attack/AD17-kdc-certificate-mapping-failure.md` |
| [AD03](AD03-ca-private-key-backup.md) | Certificate authority private key backed up or exported (golden certificate) | AD CS, priority 3 | `rules/14-ad-attack/AD03-ca-private-key-backup.md` |
| [B01](B01-horizontal-network-scan.md) | Internal port or host scanning by one process (outbound TCP to many hosts or many ports) | Scanning | `rules/11-behaviour/B01-horizontal-network-scan.md` |
| [CP04](CP04-crowdstrike-rfm-or-not-reporting.md) | CrowdStrike sensor online in Reduced Functionality Mode on a host people use | Sensor health | `rules/13-controlplane/CP04-crowdstrike-rfm-or-not-reporting.md` |
| [N12](N12-imperva-php2shell-worker-crash-burst.md) | PHP2Shell exploitation at the edge (CVE-2026-109618, CVE-2026-109619) - the upload-progress field the exploit uses, POSTs crashing PHP workers, or Imperva's own verdict | PHP2Shell | `rules/06-network/N12-imperva-php2shell-worker-crash-burst.md` |
| [CS19](CS19-php-code-runs-system-commands.md) | PHP code that runs system commands - eval'd code calling system(), exec() and the like, or a script passing request input to one (web shells, PHP2Shell follow-up) | PHP2Shell | `rules/07-crowdstrike-fdr/CS19-php-code-runs-system-commands.md` |
| [CS20](CS20-php-worker-does-something-new.md) | PHP worker (or Apache running mod_php) does something new - starts a program, writes a web script, looks up a name or connects on a port it hasn't before (PHP2Shell and web shell follow-up) | PHP2Shell | `rules/07-crowdstrike-fdr/CS20-php-worker-does-something-new.md` |

## Keeping copies and originals identical
- **In Claude Code:** the hook in `.claude/settings.json` copies an edited file over its twin after every edit.
- **By hand:** `python3 tools/sync_detection_ideas.py` syncs every pair where one side has uncommitted changes. After an edit made on GitHub, pass the file you edited: `python3 tools/sync_detection_ideas.py <file>`.
- **Check:** `python3 tools/sync_detection_ideas.py --check` fails if a copy is missing or differs from its original.
- **Adding or removing a detection:** edit the list at the top of `tools/sync_detection_ideas.py`, then run it with `--readme` to create the copy and rewrite this page.
