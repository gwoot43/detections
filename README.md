# Detection Library

Starter detection content for a new detection & response function. Stack: **CrowdStrike Falcon** (full FDR ingested), **Mimecast**, **Microsoft 365 / Entra**, **Azure**, **F5 APM** (VPN), **Imperva WAF**, **Zscaler**, all in **Elastic** following **ECS**. Queries are **ES|QL** unless a rule needs **EQL**. Coverage is mapped to **MITRE ATT&CK**.

## Layout
```
rules/
  01-cloud/                 C01-C12   Azure & Entra activity/identity-plane
  02-email/                 E01-E14   Mimecast + O365 / Defender for Office
  03-endpoint-windows/      W01-W14   CrowdStrike FDR (Windows) + Defender for Endpoint alerts
  04-endpoint-linux/        L01-L15   CrowdStrike FDR (Linux)
  05-identity/              I01-I14   Active Directory + authentication (hybrid)
  06-network/               N01-N12   F5 APM, Imperva WAF, Zscaler
  07-crowdstrike-fdr/       CS01-CS20 Falcon sensor-native telemetry
  08-correlation/           X01-X07   cross-source chains (highest value)
  09-entra-signin-extended/ S01-S23   additional high-fidelity Entra sign-on signals
  10-windows-event-logs/    WE01-WE15 Windows Security/System/Defender event-code detections
  11-behaviour/             B01-B10   behavioural (what a tool does, not its name)
  12-insider/               IN01-IN09 insider risk (SharePoint/OneDrive/Confluence/mail)
  13-controlplane/          CP01-CP06 weakening/blinding of security controls (Defender, EDR)
  14-ad-attack/             AD01-AD17 Active Directory attack paths, ranked by criticality
  15-device/                DV01-DV05 USB, keystroke injection, boot integrity, device control
  16-deception/             D01-D04   honey accounts, decoy files and hosts + setup guide
  17-ai-detections/         AI01-AI11 attacks using or aimed at AI: malware calling models, hijacked coding agents, Copilot, shadow AI
detection_ideas/            copies of the C2, tunnelling, post-exploitation and AI detections, kept identical to the originals (tools/sync_detection_ideas.py)
implement/                  copies of the detections chosen to build next (TruffleHog, AD CS), kept identical the same way
certipy_detections/         Certipy (AD CS attack tool) detections for the organisation's own schema: DC, CA and Falcon
PORTS-REFERENCE.md          ports each red/purple-team tool targets, and the detection that watches each (library-wide tuning aid)
docs/
  DETECTION-STRUCTURE-ESQL.md    how an ES|QL detection is written: the short default shape, the funnel for rules that count, baselines
  DETECTION-STRUCTURE-CQL.md     the same standard for Falcon LogScale (CQL)
  IMPLEMENTATION-TRACKER.md      tick-off checklist + build order
  NEW-TTPS-2026.md               recent tradecraft, MITRE v18-v20 changes, AI attack rules and ideas
  ESQL-CONVENTIONS.md            index patterns, METADATA, LOOKUP JOIN vs ENRICH, suppression, escaping, rule checklist
tools/
  lint_detections.py             checks every rule against the standards' reject criteria
  sync_detection_ideas.py        keeps detection_ideas/ and implement/ identical to the originals
  mitre_coverage.py              regenerates the ATT&CK coverage map
```

Each rule file is self-contained: front-matter (id, MITRE, data source, suppression), a few lines on what it catches and why, the query (ES|QL, and LogScale for CrowdStrike data), what to check before turning it on, what it misses, and what to do when it fires.

## Design principles (why these are high fidelity, not the AI-noise you have now)
1. **Alert on the improbable, not the merely suspicious.** Every rule targets behaviour with a small, knowable legitimate population you can exclude by name, not by guesswork.
2. **Prefer the transition over the state.** Block-then-success (C11, N02, N06), spray-then-success (S13-S15), disable-then-destroy (X05). Sequences are far cleaner than single events.
3. **Correlate across domains.** The X-series turns two medium signals into one certain one. These are the rules that justify having everything in Elastic.
4. **Exclude by identity, never by muting a technique.** Exclusions are entity pairs (a host and the process or service account that does this by design), never a whole host or user, and never "turn the rule off because it's noisy". The standard keeps them in one central lookup; until one exists here, they're inline placeholders.
5. **Vendor alerts are inputs, not the whole story.** CS04 routes Falcon detections in on day one; the custom rules cover what the vendors cannot see (non-endpoint sources and cross-source chains).
6. **One anchor and a corroborating property, not a list of command strings.** Anchor on what every variant of the behaviour must do. Require one property that makes it this tool or this risk, and exclude the known benign case in one precise clause. Lists of command-line variants miss the next variant and keep growing. Pattern, worked examples and a checklist for new rules: `docs/ESQL-CONVENTIONS.md` (Detection shape). B10 is the reference rule.
7. **Short by default, and every threshold has a source.** Most rules are one event, a precise regex with a named capture, and the fields to triage it (CS19). Rules that have to count or compare filter on what the index answers, reduce once per alert entity, then decide, with thresholds from a measured baseline recorded next to them (B01, CS17). Each rule says what to check before turning it on, what it misses and what to do when it fires. The standards are `docs/DETECTION-STRUCTURE-ESQL.md` and `docs/DETECTION-STRUCTURE-CQL.md`, and `tools/lint_detections.py` checks rules against them.

## Field-name caveat
Some sources are not natively ECS (F5, Imperva, Mimecast SIEM logs, some Entra properties nested under `azure.*.properties`). Queries use the closest ECS name and flag where you must confirm the real field in your ingest pipeline. Treat the queries as correct logic to be field-mapped, not copy-paste-final. Index patterns follow the Elastic integration data stream names, except CrowdStrike FDR, which comes from your own pipeline: `logs-yourorg-crowdstrike-data-default*` (replace `yourorg`), with lowercase `event.action` and raw fields under `data.*`. The mapping is in `docs/ESQL-CONVENTIONS.md` (Index patterns).

## Ports & tools reference
[`PORTS-REFERENCE.md`](PORTS-REFERENCE.md) maps every network port used across the library to what it's for, which tools target it (Certipy, Impacket, BloodHound, NetExec, ligolo, coercion, DNS tunnels, ADWS and more) and the detection that watches each. Use it when setting port/CIDR filters or checking where a tool would surface.

## Getting started
See `docs/IMPLEMENTATION-TRACKER.md`. Start with Phase 0 (Falcon passthrough + visibility protection + shared lookups), then Identity/Cloud P1, then Endpoint P1, then Email/Network P1, then the correlation rules.

## MITRE ATT&CK coverage map

The coverage map is generated from each rule's `mitre:` front-matter, so it can't drift from the rules:

- **`docs/MITRE-COVERAGE.md`**: kill-chain diagram, coverage by tactic, priority techniques with no rule, and the rules behind each technique.
- **`tools/attack-coverage-map.html`**: interactive heat map of every technique, shaded by rule count, with click-through to the rules. One self-contained file: download it and open it in a browser, or host it on an internal web server or GitHub Pages.
- **`docs/attack-navigator-layer.json`**: import into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for the standard heat map (score = number of rules).
- **`tools/mitre_coverage.py`**: regenerates all three. Run it after adding or changing a rule (usage is in the script header). The page layout lives in `tools/attack-coverage-map.template.html`.

Technique IDs follow ATT&CK v20. Since v19, Defense Evasion is split into Stealth and Defense Impairment and the old T1562 sub-techniques moved to T1685/T1686; v20 added AI techniques (T1698-T1700).

Total: 201 detections across 17 groups.
