# Sysmon → CrowdStrike FDR mapping

Most public detection logic (Sigma, blog write-ups, lab notes) is written against **Sysmon** event IDs. This estate's endpoint telemetry is **CrowdStrike Falcon FDR**, ingested to `logs-yourorg-crowdstrike-data-default*` with a lowercase `event.action`; the same events in **Falcon LogScale** use PascalCase `#event_simpleName`. This table translates between them so a Sysmon-shaped idea can be built on what we actually collect.

Two things to hold in mind:

- **Sysmon is configuration-driven, FDR is a fixed curated set.** Sysmon logs whatever its config selects (every DLL load, every registry value, every file create); FDR emits a deliberately chosen set of events, richer on some (process, DNS, network direction) and deliberately narrower on others (registry, file, image load). So several rows are **partial**, not 1:1, and that is by design, not a misconfiguration.
- **The names below marked ✓ are confirmed in use** in this library's rules. A few are standard Falcon events not currently referenced by a rule (noted); the exact `event.action` string should still be confirmed against your pipeline, per the `docs/ESQL-CONVENTIONS.md` FDR note.

## The table

| Sysmon ID | Sysmon event | CrowdStrike FDR `event.action` (Elastic) | LogScale `#event_simpleName` | Fit |
|---|---|---|---|---|
| **1** | Process creation | `processrollup2`, `syntheticprocessrollup2` ✓ | `ProcessRollup2`, `SyntheticProcessRollup2` | **1:1, richer.** FDR carries hashes, full command line, and parent/grandparent base names. `synthetic*` is the reconstructed event for a process already running when the sensor started — include both in process rules. |
| **3** | Network connection | `networkconnectip4` / `networkconnectip6` (outbound) ✓, `networkreceiveacceptip4` / `networkreceiveacceptip6` (inbound) ✓, `networklistenip4` / `networklistenip6` (listening) ✓ | `NetworkConnectIP4/6`, `NetworkReceiveAcceptIP4/6`, `NetworkListenIP4/6` | **1:1, richer.** Direction is split across distinct events, and `data.ConnectionDirection` disambiguates further — no need to infer direction as with Sysmon 3. |
| **5** | Process terminated | `endofprocess` | `EndOfProcess` | **1:1** (standard Falcon event; not currently used by a rule here). |
| **6** | Driver loaded | `driverload` ✓ | `DriverLoad` | **1:1.** |
| **7** | Image / DLL loaded | `imagehash` ✓, `reflectivedotnetmoduleload` ✓ | `ImageHash`, `ReflectiveDotnetModuleLoad` | **Partial.** No per-DLL load event like Sysmon 7. `ImageHash` hashes loaded images; reflective/.NET in-memory loads have their own event. Full module-load visibility is a gap. |
| **8** | CreateRemoteThread | `dllinjection` ✓ | `DllInjection` | **Partial / behavioural.** Falcon surfaces injection as a curated event, not a raw CreateRemoteThread for every call. |
| **9** | RawAccessRead | — | — | **Gap.** No raw-volume-read telemetry in the feed. |
| **10** | ProcessAccess (e.g. LSASS handle open) | — (Falcon detections only) | — | **Gap — a large one.** There is no general handle-open / ProcessAccess FDR event like Sysmon 10. LSASS credential access shows up as a *Falcon detection* (routed in via CS04), not as a raw FDR event you can pivot on. |
| **11** | FileCreate | `fileopeninfo`, `fspostopen`, `filerenameinfo`, `criticalfilemodified` ✓; executable/script writes via `*Written` events | `FileOpenInfo`, `FsPostOpen`, `FileRenameInfo`, `CriticalFileModified`, `*Written` | **Partial.** FDR file telemetry is event-specific (opens, renames, critical-file and executable/script writes), not a blanket FileCreate. Confirm `file.path` is populated before relying on it (see the probes in `webshell-write-and-execute.md`). |
| **12 / 13 / 14** | Registry key/value create, set, rename | `asepvalueupdate`, `reggenericvalueupdate`, `regsystemconfigvalueupdate`, `registryoperationdetectinfo` ✓ | `AsepValueUpdate`, `RegGenericValueUpdate`, `RegSystemConfigValueUpdate`, `RegistryOperationDetectInfo` | **Partial.** FDR registry telemetry is ASEP / persistence-focused and selective, not the full key/value stream Sysmon 13 gives. `registry-writes-that-matter.md` is built on exactly these. |
| **15** | FileCreateStreamHash (ADS) | — | — | **Gap.** |
| **17 / 18** | Named pipe created / connected | — (**not in this feed**) | `SmbClientNamedPipeConnectEtw` (not ingested) | **Gap.** No pipe telemetry — see `docs/VISIBILITY-GAPS.md` and `bloodhound-smb-enumeration.md`. The named-pipe method (psexec/atexec, per-interface RPC, `\pipe\cert`) is invisible. |
| **19 / 20 / 21** | WMI filter / consumer / binding | — (Falcon detections only) | — | **Gap** for raw WMI-persistence telemetry; some is covered behaviourally. |
| **22** | DNS query | `dnsrequest`, `suspiciousdnsrequest` ✓ | `DnsRequest`, `SuspiciousDnsRequest` | **1:1 (+ scored variant).** Note FDR DNS is cached at the host, so it **undercounts query volume** versus a proxy — see the DNS-cache caveat in `AI12` and `dns-tunnelling.md`. |
| **23 / 26** | FileDelete (+ archived) | — | — | **Gap** for deletes (`filerenameinfo` is adjacent but not a delete). |
| **24** | Clipboard change | — | — | **Gap.** |
| **25** | Process tampering (hollowing / herpaderping) | `dllinjection` + Falcon detections | — | **Behavioural, not raw.** |
| **29** | FileExecutableDetected | `*Written` (new-executable / PE writes), `imagehash` ✓ | `*Written`, `ImageHash` | **Partial.** |
| 2, 4, 16, 27, 28 | Timestomp / service-state / config / file-block | — / `sensorheartbeat`, `sensormetadataupdate` | — / `SensorHeartbeat` | **N/A or sensor-health.** Timestomp (2) is a behavioural detection, not raw FDR; file-block (27/28) is a prevention policy, not telemetry. |

## FDR events with no Sysmon analogue (don't translate — use directly)

Falcon curates several events Sysmon has no single equivalent for, and much of this library leans on them:

- `scheduledtaskregistered` / `scheduledtaskmodified` ✓ — Sysmon sees scheduled tasks only indirectly (process + registry). `scheduled-task-that-matters.md` uses these directly.
- `scriptcontrolscaninfo` / `scriptcontroldetectinfo` ✓, `phpevalstring` ✓ — AMSI-style script-content capture (the script body, not just the command line). Richer than anything in Sysmon.
- `userlogon` ✓ — logon telemetry from the sensor.
- `sensortampering`, `falconhostfiletamperinginfo`, `falconhostregtamperinginfo` ✓ — tamper-protection events (an attacker attacking the sensor).
- `imagehash` ✓, `osversioninfo` ✓, `sensormetadataupdate` ✓ — host/image inventory.

## The gaps that matter most

Ranked by how much offensive tradecraft they hide, the Sysmon capabilities FDR does **not** give us a raw equivalent for:

1. **ProcessAccess / LSASS handle (Sysmon 10)** — credential theft via handle open is detection-only, not pivotable in FDR.
2. **Named pipes (Sysmon 17/18)** — the lateral-movement and RPC method surface; see `VISIBILITY-GAPS.md`.
3. **Full registry stream (Sysmon 13)** — FDR is ASEP-scoped, so non-persistence registry abuse (e.g. reading stored secrets) is thin.
4. **Full image/DLL load (Sysmon 7)** — DLL search-order and sideloading detection is limited to the curated load events.
5. **WMI persistence (Sysmon 19–21)**, **file delete (23)**, **ADS (15)**, **raw-access read (9)**, **clipboard (24)** — each a gap, in roughly descending relevance.

When porting a Sysmon-based (or Sigma) rule, check it against this list first: if its anchor is one of these, the rule cannot be reproduced on FDR as written and needs a different anchor or a note that it is not deployable here.
