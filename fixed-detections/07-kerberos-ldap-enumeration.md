# 07 · Kerberos-authenticated LDAP enumeration (Linux)

**Verdict before:** weak. It fires on routine admin use of `ldapsearch` and is bypassed by a lowercase argument or any other LDAP tool.
**After:** keys on what makes enumeration suspicious, namely the LDAP filters used to find attack paths, whatever the authentication method. It also catches the common Linux AD reconnaissance tools by name.

## Before
```yaml
detection:
  selection1:
    process.command_line|contains: GSSAPI
  selection2:
    process.command_line|contains: ldapsearch
  condition: selection1 and selection2
meta:
  interval: 15m
  lookback: 60m
```

## What's wrong

| # | Problem | Effect |
|---|---|---|
| 1 | `contains: GSSAPI` is case-sensitive, but ldapsearch accepts `-Y gssapi`. | One lowercase argument bypasses the rule. |
| 2 | `ldapsearch -Y GSSAPI` is normal on domain-joined Linux hosts (sssd troubleshooting, scripts, admins checking group membership). | Fires on routine use; the analyst has nothing to tell routine from malicious. |
| 3 | Only covers ldapsearch with Kerberos. Python-based AD collectors and enumeration frameworks never contain "ldapsearch". | Most real Linux AD reconnaissance is missed. |
| 4 | No exclusions, no output context (parent, user). | Every hit needs a manual pivot. |

## After
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2"
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")),
       pname = MV_LAST(SPLIT(TO_LOWER(COALESCE(process.executable, "")), "/"))
| EVAL finding = CASE(
    pname == "ldapsearch" AND (
         cmd LIKE "*serviceprincipalname*"
      OR cmd LIKE "*admincount=1*"
      OR cmd LIKE "*1.2.840.113556.1.4.803*"
      OR cmd LIKE "*msds-allowedtodelegateto*"
      OR cmd LIKE "*msds-allowedtoactonbehalfofotheridentity*"
      OR cmd LIKE "*ms-mcs-admpwd*" OR cmd LIKE "*mslaps-*"
      OR cmd LIKE "*msds-managedpassword*"
      OR cmd LIKE "*mspki-certificate-name-flag*"),
      "ldapsearch with an attack-path filter",
    cmd LIKE "*ldapdomaindump*" OR cmd LIKE "*bloodhound-python*" OR cmd LIKE "*bloodhound.py*"
      OR cmd LIKE "*windapsearch*" OR cmd LIKE "*adidnsdump*" OR cmd LIKE "*finddelegation*"
      OR cmd LIKE "*getuserspns*" OR cmd LIKE "*getnpusers*"
      OR (cmd LIKE "*certipy*" AND cmd LIKE "* find*")
      OR ((cmd LIKE "*netexec*" OR cmd LIKE "*crackmapexec*" OR pname IN ("nxc", "cme")) AND cmd LIKE "* ldap *"),
      "ad reconnaissance tool",
    NULL)
| WHERE finding IS NOT NULL
| EVAL auth = CASE(cmd LIKE "*gssapi*", "kerberos", cmd LIKE "* -w *" OR cmd LIKE "* -y *", "password", "other")
| KEEP @timestamp, host.id, host.name, user.name, finding, auth, process.command_line, data.ParentBaseFileName, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| cmd := lower(CommandLine)
| regex("(?<pname>[^/]*)$", field=ImageFileName, strict=false)
| pname := lower(pname)
| case {
    pname="ldapsearch"
      cmd=/serviceprincipalname|admincount=1|1\.2\.840\.113556\.1\.4\.803|msds-allowedtodelegateto|msds-allowedtoactonbehalfofotheridentity|ms-mcs-admpwd|mslaps-|msds-managedpassword|mspki-certificate-name-flag/
      | finding := "ldapsearch with an attack-path filter";
    cmd=/ldapdomaindump|bloodhound-python|bloodhound\.py|windapsearch|adidnsdump|finddelegation|getuserspns|getnpusers/
      | finding := "ad reconnaissance tool";
    cmd=/certipy/ cmd=/ find/
      | finding := "ad reconnaissance tool";
    cmd=/netexec|crackmapexec/ cmd=/ ldap /
      | finding := "ad reconnaissance tool";
    in(field="pname", values=["nxc", "cme"]) cmd=/ ldap /
      | finding := "ad reconnaissance tool";
  }
| case { cmd=/gssapi/ | auth := "kerberos"; cmd=/ -w | -y / | auth := "password"; * | auth := "other"; }
| table([@timestamp, aid, ComputerName, UserName, finding, auth, CommandLine, ParentBaseFileName])
```
Suppress by `host.id`, `finding` for 6h. Severity high.

- **The filters are the signal.** Admins look up users and groups. Attack-path discovery asks for SPNs, `adminCount=1`, bitwise UAC matches (the `1.2.840.113556.1.4.803` matching rule), delegation attributes, LAPS and gMSA password attributes, and certificate template flags. Those rarely appear in routine scripts.
- **Kerberos is now context, not a condition.** The `auth` column shows whether a ticket was used. Enumeration with a stolen password is just as interesting.
- **Exclusions.** If an identity-governance or audit job runs these filters on purpose, exclude it by `data.ParentBaseFileName` or its exact command line, not by user name.

## Before vs after

| | Before | After |
|---|---|---|
| Lowercase `-Y gssapi` | Missed | Caught (case-insensitive) |
| Routine `ldapsearch -Y GSSAPI` user lookups | Alerts | Quiet |
| Attack-path LDAP filters | Only if GSSAPI was used | Caught with any authentication |
| Python AD collectors and enumeration frameworks | Missed | Caught by name |
| Context in the alert | None | User, parent process, authentication type |

## Test
From a lab Linux host joined to a test domain, run an `ldapsearch` query for `(servicePrincipalName=*)` against the lab DC. It should alert. A plain lookup of one user's group membership should not.
