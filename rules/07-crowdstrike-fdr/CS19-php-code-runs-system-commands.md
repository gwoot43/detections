---
id: CS19
name: PHP code that runs system commands - eval'd code calling system(), exec() and the like, or a script passing request input to one (web shells, PHP2Shell follow-up)
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1505.003, T1059, T1190]
data_source: CrowdStrike FDR PhpEvalString, ScriptControlScanInfo and ScriptControlDetectInfo (Linux)
suppression:
  fields: [host.name, event.action]
  duration: 1h
  missing_fields: do_not_suppress
---
Falcon sees PHP code itself, not just what it starts. `PhpEvalString` carries the code PHP is about to `eval`, after any decoding, so `eval(base64_decode(...))` shows up in the clear. `ScriptControlScanInfo` and `ScriptControlDetectInfo` carry a script's content when it's written or run. Web shells, and most PHP2Shell payloads once they have a foothold, end up calling one of PHP's command functions, so each query looks for that call and pulls it out into `Match`:

- **eval'd code** calling `system`, `shell_exec`, `exec`, `passthru`, `popen`, `proc_open` or `pcntl_exec`. Few applications eval code at all, and fewer eval code that runs a command.
- **a script** passing request input (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`) into one of those, or into `eval` or `assert`, within a few characters. That's the shape of nearly every web shell, from the one-liners up.

The `(^|[^\w$>:])` in front of the function name keeps out `curl_exec(`, `$pdo->exec(` and `Foo::exec(`.

Run every 10 minutes over the last 15.

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=PhpEvalString event_platform=Lin PhpEvalContent=/(^|[^\w$>:])(?<Match>(system|shell_exec|exec|passthru|popen|proc_open|pcntl_exec)\s{0,16}\(.{1,64})/iF
| select([@timestamp, ComputerName, Match, PhpEvalContent])
```
```logscale
#event_simpleName=/^(ScriptControlScanInfo|ScriptControlDetectInfo)$/ event_platform=Lin ScriptContent=/(^|[^\w$>:])(?<Match>(system|shell_exec|exec|passthru|popen|proc_open|eval|assert)\s{0,16}\(.{0,32}\$_(GET|POST|REQUEST|COOKIE).{0,64})/iF
| case {
   ScriptContentSource=1 | ScriptContentSource := "FILE WRITTEN";
   ScriptContentSource=2 | ScriptContentSource := "SCRIPT EXECUTED";
   * ;
}
| select([@timestamp, #event_simpleName, ComputerName, ScriptContentSource, ScriptContentName, Match, ScriptContent])
```

**Elastic (ES|QL).** `RLIKE` can't do this (no `\s`, no case flag, and it has to match the whole value), so `GROK` runs the same regex and the named group becomes the `matched` column (`Match` would collide with ES|QL's `MATCH` function).
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "phpevalstring" AND data.event_platform == "Lin"
| GROK data.PhpEvalContent """(?i)(^|[^\w$>:])(?<matched>(system|shell_exec|exec|passthru|popen|proc_open|pcntl_exec)\s{0,16}\(.{1,64})"""
| WHERE matched IS NOT NULL
| KEEP @timestamp, event.action, host.name, matched, data.PhpEvalContent, _id, _index, _version
```
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action IN ("scriptcontrolscaninfo", "scriptcontroldetectinfo") AND data.event_platform == "Lin"
| GROK data.ScriptContent """(?i)(^|[^\w$>:])(?<matched>(system|shell_exec|exec|passthru|popen|proc_open|eval|assert)\s{0,16}\(.{0,32}\$_(GET|POST|REQUEST|COOKIE).{0,64})"""
| WHERE matched IS NOT NULL
| EVAL data.ScriptContentSource = CASE(TO_STRING(data.ScriptContentSource) == "1", "FILE WRITTEN",
                                       TO_STRING(data.ScriptContentSource) == "2", "SCRIPT EXECUTED",
                                       TO_STRING(data.ScriptContentSource))
| KEEP @timestamp, event.action, host.name, data.ScriptContentSource, data.ScriptContentName, matched, data.ScriptContent,
       _id, _index, _version
```
Suppress by host and event for an hour, so a web shell in use is one alert an hour, not one per command.

## Before turning it on
- Check which hosts send these events at all. Script Control has to be on in the Linux prevention policy.
  ```logscale
  #event_simpleName=/^(PhpEvalString|ScriptControlScanInfo|ScriptControlDetectInfo)$/
  | groupBy([#event_simpleName, event_platform], function=[count(), count(aid, distinct=true, as=hosts)], limit=max)
  ```
- In Elastic, check the content fields arrive whole. A keyword mapping with `ignore_above`, or the pipeline, can cut long scripts short.
- Run each query over 30 days. Anything that fires every day is an application doing it on purpose; exclude that host and script name, not the host.

## What it misses
- A function name built at runtime (`$f = 'sys'.'tem'; $f($x)`, `call_user_func`, backticks) in a script. In eval'd code `PhpEvalString` still shows the call, as long as it's spelled out by the time it reaches `eval`.
- A web shell that reads its input from somewhere else (`$_SERVER` headers, `php://input`, a file), or keeps more than 32 characters between the call and the input.
- Code that never goes through `eval` or a scanned script. PHP2Shell's own payload runs in memory before PHP reads any script; CS20 catches what the PHP process starts or connects to, and N12 the attempt at the edge.
- Hosts other than Linux. Drop `event_platform=Lin` if you run PHP elsewhere.

## When it fires
- `FILE WRITTEN`: the file in `ScriptContentName` is almost certainly a web shell. Find the request that dropped it in the web server's access log and quarantine the file.
- `SCRIPT EXECUTED` or `PhpEvalString`: something is using it now. Check CS20 for what the PHP worker started or connected to, the access log for the requests around `@timestamp`, and the PHP version (PHP2Shell is fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35).
