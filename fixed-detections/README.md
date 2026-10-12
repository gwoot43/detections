# Fixed detections: before and after

Reviews of eight existing production detections (Kerberoasting, C2 and tunneling), each with the original query, what's wrong with it, a corrected query, and a before/after table. The corrected queries are ES|QL and use the **organisation's own schema** (`logs-<org>-crowdstrike-data-default*` with `data.*` fields and lowercase `event.action`, and `logs-<org>-microsoft-windows*` with `winevt.event_data.*`), not the Elastic-integration field names used in `rules/`.

## Summary

| # | Rule | Before | Main problems | After |
|---|---|---|---|---|
| 01 | [Tunnel service connection (Zscaler)](01-tunnel-service-connection.md) | Fires (one copy only) | Copy 1 has an exact-match domain that never matches; QUIC tunnels invisible to the proxy; 3 services covered | Zscaler rule with 12 services in tiers, plus a Falcon rule that sees the tunnel agent (port 7844, renamed binaries, `code tunnel`, ssh `-R`/`-D`) |
| 02 | [DNS tunneling](02-dns-tunneling.md) | **Cannot fire** | `like "."` matches nothing; counts repeats of one name, which isn't what tunneling looks like | Distinct names per parent domain with long labels or TXT/NULL types; `.com.au`-aware; 6 exclusions instead of ~75 |
| 03 | [Credential or tunneling tool arguments](03-credential-and-tunnel-tool-arguments.md) | Fires, weakly | `NOT user.name:*$` likely hides SYSTEM; mimikatz one-liners only; two behaviours in one rule | Credential-dumping rule (comsvcs, procdump, SAM/SECURITY hive save, mimikatz one-liners); tunneling moved to 01 |
| 04 | VS Code internal sensitive ports | Fires, noisy | Not included in this round | Not included in this round |
| 05 | [Browser internal remote-access ports](05-browser-internal-remote-access-ports.md) | Fires, noisy | SMB at one connection; exclusion breaks with a second target | RDP/WinRM on any connection, SMB at 3+ targets; per-event exclusion; 7 browsers |
| 06 | [Kerberoasting](06-kerberoasting.md) | Fires, only for loud RC4 attacks | Split per DC; fixed 5-minute buckets; RC4 only; 10-service threshold | Per requester across DCs, RC4 tier at 3, any-encryption tier at 15, plus a honey SPN check |
| 07 | [Kerberos LDAP enumeration (Linux)](07-kerberos-ldap-enumeration.md) | Fires on routine use | Case-sensitive; flags normal `ldapsearch`; misses other tools | Attack-path LDAP filters with any auth, plus AD recon tools by name |
| 08 | [Linux Kerberos credential cache](08-linux-kerberos-credential-cache.md) | **Almost certainly never fires** | Requires a detection-only field on a process event; excludes all EC2 hosts; watches benign `klist` | Any process touching ticket caches, keytabs or the SSSD store, except known Kerberos tooling; no fleet or person exclusions |

## Patterns that broke several rules
- **`LIKE` without `*`** is an exact match in ES|QL (02).
- **Excluding `user.name` ending in `$`** may hide SYSTEM activity on Falcon events (03), and doesn't remove `host$@DOMAIN` requesters on 4769 (06).
- **Fixed `DATE_TRUNC` buckets** split activity at bucket edges (02, 05, 06). Use the rule's lookback window and suppression instead.
- **Grouping by `host.name`** collapses hosts when Falcon's host enrichment is missing (05), and on 4769 it is the DC, not the attacker (06). Prefer `host.id` for Falcon and the requester for Windows authentication events.
- **Named people, hosts and whole fleets in exclusions** (08). Exclude automation by its exact parent or command line instead.
- **`SORT` and `LIMIT` in rules** do nothing useful and can cap alerts.

## Placeholders in this public copy
Org-specific values are replaced so the repo carries no internal identifiers. Swap them back before deploying:

| Placeholder | Replace with |
|---|---|
| `yourorg` in index names | Your index prefix |
| `corp-internal.example`, `corp-legacy.example` | Your internal DNS domains |
| `192.0.2.10` | Your approved WinRM gateway IP |
| `excluded_user_1`, `automation_account`, `excluded-host-1` | Names from the original rule (only in the "before" sections) |
| `<honey_service_account>` | Your honey SPN account (rule 06) |

## Check in Discover before enabling
1. Falcon process events for SYSTEM-context processes: what `user.name` looks like (rules 01, 03).
2. `data.RequestType` exists on `dnsrequest` events and holds numbers (rule 02).
3. 4769 `user.name` format, e.g. `user@DOMAIN` or `host$@DOMAIN` (rule 06).
4. `process.command_line` mapping: if the keyword field has `ignore_above`, long command lines are invisible to ES|QL. Encoded payloads are often long.
5. The Zscaler index name for rule 01 After A (the original KQL rule didn't name one).
