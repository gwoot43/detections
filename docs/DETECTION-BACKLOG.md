# Detection backlog — ideas not yet in the catalogue

Ten candidates, each checked against `rules/` before it was written here. Ordered by build cost, cheapest first,
because the cheap ones are the ones that ship. Every entry states what it anchors on, why nothing in the repo
already covers it, and the benign twin that will otherwise make it noisy.

Two of them need a field confirmed before they are worth building; they are marked **probe first**.

---

## 1. Tunnelling and pivoting

`CS14` covers named tunnel services by their ports (Cloudflare, ngrok, Tailscale, ZeroTier, bore). `CS24` covers an
external `ssh -R`. `CS13` covers a VS Code tunnel. `CS03` covers DNS by uniqueness. Everything below catches what
those four cannot: a **renamed or self-hosted** tunnel, which is what a tester or an operator running their own
ingress looks like.

### 1.1 Reverse-tunnel fan-in — the pivot's shape

**Anchor:** one host accepts inbound connections on a single port from **many internal sources** while itself
holding **exactly one external peer**. Many-in, one-out is a SOCKS proxy behind a tunnel.

**Why new:** `CS14` keys on known ports, `L14` is Linux-only, and nothing measures the inversion. Catches chisel
`client … R:socks`, ligolo, `socat` and a self-hosted ngrok edge alike, with no process name and no port list.

**Benign twin:** a jump host or a load balancer has the same shape — but it has *several* external peers and it
listens on a documented port. Restrict to a non-standard listen port or a rare `(host, port)` pair.

**Cost:** medium. Needs both directions from FDR and a per-host baseline.

### 1.2 A new listening port on an endpoint

**Anchor:** `networklistenip4` where the `(host, port)` pair is rare fleet-wide — nobody else binds 4444, 9001,
31337, 1080.

**Why new:** there is no Windows listener rule in the repo at all; `L14` is the Linux twin. This is where chisel
`server`, `ligolo -selfcert`, `socat` and a bind shell all live.

**Benign twin:** developer tooling binds high ports constantly (Node, Docker, WSL). Fleet rarity plus a
per-user baseline is what makes it quiet, not a port list.

**Cost:** low. One event, one rarity join.

### 1.3 DNS tunnelling seen from the resolver

**Anchor:** the internal DNS server's own recursive queries: high unique-name ratio outbound to one external
resolver.

**Why new:** `CS03` runs on endpoints, so it is blind to unmanaged and BYOD hosts. Every tunnelled query still has
to be recursed by your resolver, so one rule there covers the whole estate.

**Benign twin:** a forwarder resolving normal internet traffic has high name diversity but a **low** uniqueness
ratio (the same names recur). The ratio, not the volume, separates them.

**Cost:** medium. Only works if the resolver is a Falcon-managed host or you log its queries.

### 1.4 DNS straight to an external resolver

**Anchor:** `networkconnectip4` to port 53 where the destination is not your resolver.

**Why new:** this is the gap `CS03` documents in its own blind-spot note. `N09` covers DoH through the proxy; a raw
`:53` to `8.8.8.8` never touches the proxy at all. Also catches TCP/53, which normal clients never use.

**Benign twin:** none worth allowing. A client that skips the estate resolver is either misconfigured or evading.

**Cost:** low. One filter, no thresholds.

---

## 2. Domain-controller specific

### 2.1 Domain policy changed

**Anchor:** `4739` — lockout threshold, maximum ticket lifetime, "store passwords with reversible encryption".

**Why new:** no rule in the repo reads `4739`. It fires a handful of times a year, always by a tier-0 admin, and
every variant is a privesc enabler: raising the lockout threshold turns a spray into unlimited attempts, extending
ticket lifetime extends a golden ticket, reversible encryption recovers plaintext.

**Benign twin:** a documented policy review. Alert on the change, not on the value — the triage is "who asked for
this".

**Cost:** low. One event, no threshold.

### 2.2 Replication topology changed — and yes, this is where DCShadow lives

**Anchor:** `4929` (replica source added), `4930` (modified), `4931` (naming context removed), `4928` (naming
context established).

**Combining it with DCShadow:** DCShadow does not touch replication *policy*, it stands up a temporary rogue DC:
it creates an `nTDSDSA` object (`5137`), **adds a replication source for a naming context (`4929`)**, pushes its
changes, then removes both (`5137` delete, `4931`). `AD01` watches the directory objects (`5136`/`5137`); this rule
watches the **replication plumbing**. Together they close the technique from both ends, and the correlation that
makes it near-certain is the **sequence**: a replica source added and a naming context removed inside the same short
window, from a host that is not a known DC.

**Why new:** outside a DCPromo the baseline is zero, and nothing in the repo reads `4929`/`4931` at all.

**Benign twin:** a real DC promotion or decommission — which is a change ticket, and rare enough to allowlist by
host.

**Cost:** low for the single events, medium for the sequence.

### 2.3 A DC as the SMB client

**Anchor:** `4624` type 3 where the **source** is a domain controller and the target is a workstation or member
server.

**Why new:** everyone detects authentication *to* a DC. Almost nobody detects a DC authenticating outward, which is
exactly what an attacker holding a DC's machine account does next.

**Benign twin:** replication, backup and monitoring — a tiny allowlist of target hosts, not a threshold.

**Cost:** low. One event, one field comparison, one allowlist.

---

## 3. Lateral movement and privilege escalation

### 3.1 S4U2Proxy abuse — the delegation case `AD08` filters out  
**Shipped:** `AD20`.

**How it works.** Kerberos delegation has two halves. `S4U2Self` lets a service ask the KDC for a ticket *to
itself* on behalf of any user — no delegation rights needed. `S4U2Proxy` then lets that service present the user's
ticket to a **second** service and receive a ticket to it, which is only permitted when the first service has
constrained delegation (`msDS-AllowedToDelegateTo`) or the target computer has resource-based constrained delegation
(`msDS-AllowedToActOnBehalfOfOtherIdentity`) pointing at it.

**Why it is an attack.** Whoever controls a service that can proxy can become **any user** to the target service —
including a domain admin to a DC's LDAP or CIFS SPN. Two routes in: compromise a service already trusted to
delegate, or grant yourself the right (`GenericWrite` on a computer object is enough to set RBCD).

**The anchor.** The proxied ticket carries its chain in `TransitedServices`. A `4769` for the target SPN with a
**non-empty `TransitedServices`**, where the requesting account is not delegated to that SPN, is S4U2Proxy in use.

**Why nothing sees it today.** `AD08` excludes exactly these rows — it treats `TransitedServices != "-"` as
"normal delegation" and moves on. So the one ticket rule in the catalogue deliberately looks away from the abuse
case. `I14` catches delegation being *configured*, not being *used*.

**Making it quiet.** Normal constrained delegation produces the same `(account, target SPN)` pairs every day, so
the rule is pair rarity: a transited ticket for a pair that is new fleet-wide, or a target SPN the account's
`msDS-AllowedToDelegateTo` does not list. With RBCD, the delegation list lives on the *target* computer object, so
the same check needs both sides of the relationship.

**Benign twin:** a legitimate multi-hop service (a web tier delegating to a database) — which is why the pair has to
be baselined rather than alert on first sight.

**Cost:** medium-high. Needs the delegation reference lists, and `TransitedServices` confirmed as populated.

### 3.2 Workstation-to-workstation SMB

**Anchor:** `4624` type 3 where **both** source and target are workstations, and the pair is fleet-rare.

**Why new:** `WE12` catches the pass-the-hash logon *shape*; nothing catches the impossible *relationship*. A user's
PC has no reason to authenticate to another user's PC.

**Benign twin:** helpdesk tools and SCCM peer caching — a small set of source accounts, allowlisted.

**Cost:** low-medium. Needs a workstation list and a pair baseline.

---

## 4. Entra — the audit side is missing

The `S` series is almost entirely **sign-in log** detections. Directory changes live in the **audit log**, and that
is where cloud privilege escalation and persistence happen — the Entra equivalent of `5136`. Five candidates:

### 4.1 Permanent privileged role assignment, outside PIM  
**Shipped:** `S25`.

**Anchor:** audit `Add member to role` for a privileged role where the activity is not a PIM activation
(`Add member to role completed (PIM activation)`), or `Add member to role outside PIM`.

**Why:** PIM activations are temporary and audited by the PIM UI; a **permanent** assignment is persistence, and it
is what an attacker with `Privileged Role Administrator` or a compromised Global Admin does first. The audit log
distinguishes the two, so the rule is precise without a threshold.

### 4.2 A credential added to an app, then used

**Anchor:** audit `Add service principal credentials` or `Update application – Certificates and secrets management`,
then a **service principal sign-in** for that app from a new IP within hours.

**Why:** adding a secret is a normal admin action and invisible on its own; the pairing is the fidelity. This is
cloud persistence that survives password resets and MFA.

### 4.3 Illicit consent grant

**Anchor:** `Consent to application` or `Add OAuth2PermissionGrant` where the app is newly registered, the
consenting user is not an admin, and the scope includes mail, files or `offline_access`.

**Why:** consent phishing gives an attacker a refresh token without a password. `S24` covers app *probing*; nothing
covers the grant.

### 4.4 Conditional Access policy weakened or disabled  
**Shipped:** `S26` — the cloud twin of `WE02`, and the two now cross-reference each other.

**Anchor:** `Update conditional access policy` where `state` moves to disabled, or an exclusion is added for a
group or user.

**Why:** this is the cloud twin of `WE02`'s audit-policy change — the "can I blind you" step, done in the portal
instead of on a DC. Rare, always by an admin, and always worth a conversation.

### 4.5 Authentication method registered, then used from a new network

**Anchor:** `User registered security info` (an authenticator or phone added) followed by a sign-in using that
method from a new IP or ASN within minutes.

**Why:** `S11` covers an admin **resetting** MFA; this covers an attacker **adding** their own method to an account
they already hold, which is the quieter persistence route.

---

## Held back

These were considered and not listed, so they are not silently dropped: unconstrained delegation granted after
creation (`4738`, `0x80000`), `4672` immediately after an inbound network logon, and tombstone reanimation. The
first two are sound but need a tier-0 reference list that does not exist yet; the third depends on `5136`, which is
unverified on this pipeline.
