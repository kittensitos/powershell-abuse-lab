# Detections and the log evidence that fires them

Seven rules. For each one: the exact log, the exact event ID, the exact field, and the
exact condition. If a rule fires, one of these fields contained one of these patterns —
there is no other path to a finding.

Implemented in `03-Invoke-Detections.ps1`. Every finding it emits carries `LogName`,
`EventId`, `EvidenceField` and `Evidence`, so a hit always shows its own provenance.

---

## Evidence sources

| Source | Log | Enabled by |
|---|---|---|
| Script block text | `Microsoft-Windows-PowerShell/Operational` **4104** | `EnableScriptBlockLogging` |
| Pipeline / module detail | `Microsoft-Windows-PowerShell/Operational` **4103** | `EnableModuleLogging` |
| Engine start | `Windows PowerShell` (classic) **400** | on by default |
| Process creation | `Security` **4688** | audit policy + `ProcessCreationIncludeCmdLine_Enabled` |
| Process access | `Microsoft-Windows-Sysmon/Operational` **10** | Sysmon, optional |

`01-Enable-Logging.ps1` turns on everything except Sysmon.

The property that makes 4104 the backbone of this lab: **it records a script block when the
block is compiled, not when it runs.** Text that is parsed and discarded is still logged in
full. That is why `02-Invoke-Simulations.ps1` can produce genuine, full-fidelity tradecraft
evidence without executing any of it.

---

## D1 — Base64 encoded command

**T1027.010 / T1059.001** · Severity High

| | |
|---|---|
| Primary log | `Security` **4688** |
| Primary field | `CommandLine` |
| Condition | `(?:^|\s)-e[a-z]*\s+[A-Za-z0-9+/=]{20,}` and image is `powershell.exe`/`pwsh.exe` |
| Secondary log | `Microsoft-Windows-PowerShell/Operational` **4104** |
| Secondary field | `ScriptBlockText` contains `FromBase64String` (Medium) |

PowerShell accepts any unambiguous abbreviation of `-EncodedCommand`, so `-e`, `-en`, `-enc`
and `-encod` all work and the pattern has to allow all of them. The 20-character base64
minimum is what keeps `-ExecutionPolicy Bypass` out: it also starts with `-e`, but `Bypass`
is six characters and never satisfies the length floor.

**False positives:** some management agents and installers legitimately use `-EncodedCommand`
to pass quoted arguments safely. Baseline the parent process before alerting.

---

## D2 — Download cradle into Invoke-Expression

**T1059.001 / T1105** · Severity High

| | |
|---|---|
| Log | `Microsoft-Windows-PowerShell/Operational` **4104** |
| Field | `ScriptBlockText` |
| Condition A | `DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|Start-BitsTransfer` |
| Condition B | `Invoke-Expression|\bIEX\b` |
| Fires when | **both** A and B match the same script block |

Requiring both is the whole rule. Downloading a file is ordinary. Calling `Invoke-Expression`
is ordinary. Fetching remote content and immediately executing it as code in the same block
is the fileless-delivery pattern, and it is rare in legitimate scripts.

**False positives:** package bootstrappers do exactly this — the Chocolatey and
`Install-Module` install one-liners are textbook cradles. Allowlist by URL or by the
signature of the invoking process rather than weakening the rule.

**Known gap:** obfuscation that splits the strings (`'IE'+'X'`, backtick insertion,
`&('I'+'EX')`) defeats plain substring matching. AMSI often flags those blocks anyway, so
`Level=Warning` on a 4104 is a useful independent signal — see D3.

---

## D3 — AMSI tampering indicators

**T1562.001** · Severity High

| | |
|---|---|
| Log | `Microsoft-Windows-PowerShell/Operational` **4104** |
| Field | `ScriptBlockText` |
| Condition | `AmsiUtils|amsiInitFailed|AmsiScanBuffer|AmsiOpenSession|AmsiContext` |
| Corroboration | same event's `Level` is `Warning` |

Single-condition and still very low noise, because nothing legitimate reaches into
`System.Management.Automation.AmsiUtils`. Its only purpose is to disable the scanner.

The `Level=Warning` corroboration is worth understanding. Script block logging normally
writes at `Verbose` (5). When AMSI's own heuristics flag the content, the same event is
written at `Warning` (3) instead. So the event carries an independent verdict from a
different engine, alongside the text. A 4104 at `Warning` is worth reviewing even when no
rule in this file matches its text.

---

## D4 — In-memory injection API surface

**T1055 / T1620** · Severity Medium

| | |
|---|---|
| Log | `Microsoft-Windows-PowerShell/Operational` **4104** |
| Field | `ScriptBlockText` |
| Condition | `VirtualAlloc(Ex)?|WriteProcessMemory|CreateRemoteThread(Ex)?|NtCreateThreadEx|QueueUserAPC|GetDelegateForFunctionPointer|\[(System\.)?Reflection\.Assembly\]::Load` |

The allocate / write / execute trio plus the reflective loading APIs. A PowerShell script
that needs `VirtualAlloc` is doing something a script has no ordinary reason to do.

Medium rather than High because the legitimate tail is real: some monitoring agents,
driver installers and P/Invoke-heavy admin modules name these APIs. Raise to High when it
lands on the same host as a D2 or D3 hit within a short window.

---

## D5 — LSASS credential dumping

**T1003.001** · Severity High

Two independent paths.

| Path | Log | Field | Condition |
|---|---|---|---|
| Text | PowerShell/Operational **4104** | `ScriptBlockText` | `MiniDumpWriteDump\|comsvcs\.dll\s*,?\s*MiniDump\|Out-Minidump\|lsass\.dmp\|procdump.{0,40}lsass` |
| Behaviour | Sysmon **10** | `GrantedAccess` | `TargetImage` ends `\lsass.exe` **and** `GrantedAccess` in `0x1010, 0x1410, 0x1438, 0x143a, 0x1f1fff, 0x1fffff` |

The Sysmon path is the higher-fidelity one, and the difference between the two is the point.
The 4104 path proves someone *wrote* dumping code. The Sysmon path proves a process *opened
a handle to LSASS with read access* — an observed behaviour, not a string. Renaming variables
defeats the first and does nothing to the second.

Those access masks all include `PROCESS_VM_READ` (`0x0010`), which is what you need to read
another process's memory. `0x1fffff` is `PROCESS_ALL_ACCESS`.

**The simulation cannot exercise the Sysmon path.** `02-Invoke-Simulations.ps1` will not dump
LSASS, because doing so writes real credential material to disk and there is no partial
version of that. S5 tests the 4104 branch only; the Sysmon branch is correct code that this
lab cannot fire. Validate it against a purpose-built range if you need it proven.

**False positives:** legitimate AV, EDR and backup agents open LSASS handles constantly.
Filter on `SourceImage` before this is usable in production.

---

## D6 — Suspicious launch flag combination

**T1059.001 / T1564.003** · Severity High

| | |
|---|---|
| Primary log | `Security` **4688** |
| Primary field | `CommandLine` |
| Fallback log | `Windows PowerShell` (classic) **400** |
| Fallback field | `HostApplication` line inside the event message |
| Fires when | **two or more** distinct flag families appear |

Flag families:

| Family | Pattern |
|---|---|
| NoProfile | `(?:^\|\s)-nop(rofile)?\b` |
| HiddenWindow | `-w(indowstyle)?\s+hidden\b` |
| BypassPolicy | `-e[a-z]*\s+(bypass\|unrestricted)\b` |
| NonInteractive | `(?:^\|\s)-noni(nteractive)?\b` |
| EncodedCommand | `(?:^\|\s)-e[a-z]*\s+[A-Za-z0-9+/=]{20,}` |

Any single flag is unremarkable — scheduled tasks are `-NonInteractive`, installers use
`-ExecutionPolicy Bypass`. The threshold of two is what carries the rule: stacking them is
what malicious shortcuts, macro droppers and operator tooling do, and what routine
automation generally does not.

Expect simulation S1 to raise a D6 finding as well as a D1 one: its command line is
`-NoProfile -EncodedCommand <blob>`, which is two families. That is the rule working, not
double-counting.

The classic-400 fallback is the part worth stealing for real environments. `HostApplication`
inside event 400 contains the full launching command line, and it is populated **whether or
not** anyone ever enabled `ProcessCreationIncludeCmdLine_Enabled`. On hosts where 4688
command line auditing was never turned on, this is often the only surviving record of how
PowerShell was invoked.

---

## D7 — PowerShell v2 engine downgrade

**T1562.001** · Severity High

| | |
|---|---|
| Log | `Windows PowerShell` (classic) **400** |
| Field | `EngineVersion` line inside the event message |
| Condition | `EngineVersion=2.0` |

One line of matching, and it matters more than its size suggests. The v2 engine predates
AMSI and script block logging entirely, so `powershell -version 2` turns off D2 through D5
in a single flag. The attack is not what runs under v2; it is the downgrade itself.

You cannot alert on the resulting absence of 4104 events. You can alert on this, because the
classic log still records the engine version. Near-zero false positive rate — legitimate v2
use on a modern estate is essentially extinct.

`04-Enable-Blocking.ps1` removes the v2 engine, which is the real fix. Keep the detection
anyway, for the hosts the removal has not reached.


## Limitations

**Large script blocks are split.** 4104 events carry `MessageNumber` and `MessageTotal`.
A block over roughly 20 KB is written as several events, and a pattern straddling the
boundary is missed by all of them. Reassembling by `ScriptBlockId` before matching fixes
this; `03-Invoke-Detections.ps1` does not, and the lab's own blocks are far too small to
hit it.

**String matching loses to obfuscation.** Every rule except the Sysmon branch of D5 matches
text. Concatenation, backticks, format operators, `char[]` arrays and `-join` all defeat
them. This is a structural property of content matching, not a bug to fix here the real
answers are AMSI's `Level=Warning` signal, behavioural telemetry, and the ASR obfuscation
rule in `04-Enable-Blocking.ps1`.

**The lab's own files match its own rules.** All four `.ps1` files contain these indicators
as literal text, so `03-Invoke-Detections.ps1` skips 4104 events whose `Path` is one of them.
Run it with `-IncludeLabFiles` to watch every rule fire on the lab itself. Worth doing once:
security tooling tripping content rules is a real operational problem, and this is the
smallest honest example of it.

**Severities are lab defaults.** They assume no baselining. In a real environment, most of
what determines severity is the parent process, the signer and the user — none of which
these rules consider.
