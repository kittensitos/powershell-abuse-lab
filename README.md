# powershell-abuse-lab

A small, self-contained lab for PowerShell attack telemetry: turn on the logging, generate
the evidence for seven common techniques, catch them with seven detections, then block them.

Every detection names the exact log, event ID and field that fired it. Nothing here is a
black box, and nothing here attacks the host it runs on.

## Safety

**The simulations do not attack the machine.** No working AMSI bypass, no shellcode, no
credential dumping, no network payload, no persistence.

They work because of one property of Script Block Logging:

> Script Block Logging records the text of a script block when the block is **compiled**,
> not when it runs.

So `[ScriptBlock]::Create('<real tradecraft text>')` writes a complete, full-fidelity 4104
event, and then the block is discarded without ever being invoked. The detections see text
they cannot distinguish from the real thing, which is the point — the rules get a genuine
test. Meanwhile the only things that actually execute are two child processes running
`Write-Output`.

Two consequences worth knowing up front:

- One technique cannot be simulated honestly. D5's high-fidelity evidence is a Sysmon
  handle-open against LSASS, and there is no safe partial version of dumping LSASS. S5
  exercises D5's script-text branch only. `DETECTIONS.md` says so where it matters.
- **Your EDR will probably alert on some of this.** That is the correct outcome. Run it on
  a disposable VM you control, and tell your SOC first if the machine is monitored.

## Requirements

Windows, PowerShell 5.1 or later, and an elevated session for scripts 01 and 04.
Sysmon is optional — one branch of D5 uses it and is skipped if it is absent.

## Quick start

```powershell
# 1. Turn on the telemetry (elevated)
.\01-Enable-Logging.ps1

# 2. Open a NEW PowerShell window. This matters - see below.

# 3. Generate the evidence
.\02-Invoke-Simulations.ps1

# 4. Catch it
.\03-Invoke-Detections.ps1 -SinceMinutes 10

# 5. Block it (elevated; audit mode by default)
.\04-Enable-Blocking.ps1
```

Step 2 is not optional. A session that started before script block logging was enabled has
already read the old policy and will not emit 4104 events, so simulations S2 through S5
produce nothing and the run looks like a detection failure when it is a setup problem.

To see what the simulations would do without running them:

```powershell
.\02-Invoke-Simulations.ps1 -ListOnly
```

To undo the logging changes:

```powershell
.\01-Enable-Logging.ps1 -Revert
```

## Coverage

| | Technique | MITRE | Fires on |
|---|---|---|---|
| **D1** | Base64 encoded command | T1027.010 | Security **4688** `CommandLine` |
| **D2** | Download cradle into `IEX` | T1059.001, T1105 | PowerShell **4104** `ScriptBlockText` |
| **D3** | AMSI tampering | T1562.001 | PowerShell **4104** `ScriptBlockText` + `Level=Warning` |
| **D4** | In-memory injection APIs | T1055, T1620 | PowerShell **4104** `ScriptBlockText` |
| **D5** | LSASS credential dumping | T1003.001 | PowerShell **4104** + Sysmon **10** `GrantedAccess` |
| **D6** | Suspicious launch flags | T1059.001, T1564.003 | Security **4688** `CommandLine`, or classic **400** `HostApplication` |
| **D7** | PowerShell v2 downgrade | T1562.001 | Classic **400** `EngineVersion=2.0` |

Full conditions, regexes, false-positive notes and limitations: **[DETECTIONS.md](DETECTIONS.md)**.

## Files

| File | What it does |
|---|---|
| `01-Enable-Logging.ps1` | Script block logging (4104), module logging (4103), transcription, and 4688 with command line. `-Revert` undoes it. |
| `02-Invoke-Simulations.ps1` | Emits evidence for seven techniques. `-ListOnly` to preview, `-Only S1,S3` for a subset. |
| `03-Invoke-Detections.ps1` | Runs the seven rules, prints the matched field and substring per hit, emits objects to the pipeline. |
| `04-Enable-Blocking.ps1` | Removes the PowerShell v2 engine and sets four Defender ASR rules. Audit mode unless `-Enforce`. |
| `DETECTIONS.md` | Rule-by-rule evidence mapping. |

## Design notes

**Detections match tradecraft, not the lab.** The simulator stamps each run with a
`PSLAB-xxxxxxxx` marker, but no rule matches on it. The marker only scopes the time window
and proves a run happened. If a rule fires, it fired on a real indicator.

**Findings are objects.** `03-Invoke-Detections.ps1` writes a formatted console report and
returns finding objects, so you can pipe them:

```powershell
$findings = .\03-Invoke-Detections.ps1 -SinceMinutes 30 -Quiet
$findings | Where-Object Severity -eq 'High' | Format-List
$findings | Export-Csv .\findings.csv -NoTypeInformation
```

**The lab detects itself, and that is filtered by default.** All four scripts contain the
indicators as literal text, so 4104 events whose `Path` is one of the lab files are skipped.
Pass `-IncludeLabFiles` to turn the filter off and watch every rule fire on the lab. Worth
doing once — security tooling tripping content rules is a real operational problem.

**Execution policy is not configured, deliberately.** It is not a security boundary.
Simulation S6 walks through it with `-ep bypass` by design. `04-Enable-Blocking.ps1` says
this in its own output rather than quietly leaving it out.

**ASR rules default to audit.** Audit logs what would have been blocked without blocking it,
which is how you discover what legitimate work a rule breaks before it breaks it. Check
event **1122** in `Microsoft-Windows-Windows Defender/Operational`, then re-run with
`-Enforce`.

## Where this stops

These are string-matching rules on a handful of fields. Concatenation, backticks, format
operators and `-join` defeat most of them, which is a property of content matching rather
than a bug to fix here. The honest extensions are AMSI's `Level=Warning` signal, behavioural
telemetry like Sysmon, and the ASR obfuscation rule in `04-Enable-Blocking.ps1`.

Severities assume no baselining. In a real environment the parent process, the signer and
the user account decide severity, and none of these rules look at any of them.
