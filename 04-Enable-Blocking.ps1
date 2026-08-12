#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the preventive controls that actually stop the techniques the lab simulates.

.DESCRIPTION
    Detection tells you it happened. These controls stop it. Four of them, chosen because
    each one maps directly to a technique in this lab:

      1. Remove the PowerShell v2 engine     kills D7, and restores visibility for D2-D5
      2. Defender ASR rules                  blocks obfuscated scripts, LSASS theft,
                                             PSExec/WMI child processes, WMI persistence
      3. Confirm AMSI is live                the precondition for D3 being meaningful
      4. Report on Constrained Language Mode which is only real if WDAC/AppLocker enforces it

    ASR rules default to AUDIT mode. Audit logs what would have been blocked without
    blocking it, which is how you find out what legitimate work a rule would break before
    it breaks it. Re-run with -Enforce once the audit events look clean.

    What this script deliberately does NOT do:
      - Set an ExecutionPolicy. It is not a security boundary and never has been. It stops
        accidents, not attackers; -ExecutionPolicy Bypass and a dozen other flags defeat it
        by design. Setting it here would imply a protection that does not exist.
      - Configure WDAC or AppLocker. Those are the controls that make Constrained Language
        Mode enforceable, but a wrong policy locks you out of the machine, so they need to
        be authored and tested deliberately rather than applied by a lab script.

.PARAMETER Enforce
    Set ASR rules to Block instead of Audit.

.PARAMETER SkipPSv2Removal
    Leave the v2 engine alone. Removal usually wants a reboot.

.PARAMETER Revert
    Set the ASR rules this script manages back to Disabled. Does not reinstall v2.

.EXAMPLE
    .\04-Enable-Blocking.ps1

.EXAMPLE
    .\04-Enable-Blocking.ps1 -Enforce

.NOTES
    Requires Microsoft Defender Antivirus in active mode. ASR rules are ignored if Defender
    is in passive mode behind another AV product.

    Rule IDs verified against Microsoft's "Attack surface reduction rules reference",
    July 2026. Note that Microsoft's own configuration page has a typo in the WMI
    persistence GUID (a truncated final character) - the value below is the correct one.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $Enforce,
    [switch] $SkipPSv2Removal,
    [switch] $Revert
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step { param([string] $Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string] $Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warn { param([string] $Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Info { param([string] $Message) Write-Host "    $Message" -ForegroundColor DarkGray }

# ======================================================================================
# ASR rules relevant to PowerShell abuse
# ======================================================================================

$AsrRules = @(
    [pscustomobject]@{
        Id     = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
        Name   = 'Block execution of potentially obfuscated scripts'
        Covers = 'D1 encoded commands, D2 cradles'
    }
    [pscustomobject]@{
        Id     = '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'
        Name   = 'Block credential stealing from the local security authority subsystem'
        Covers = 'D5 LSASS dumping'
    }
    [pscustomobject]@{
        Id     = 'D1E49AAC-8F56-4280-B9BA-993A6D77406C'
        Name   = 'Block process creations originating from PSExec and WMI commands'
        Covers = 'lateral movement that lands as a PowerShell child process'
    }
    [pscustomobject]@{
        Id     = 'E6DB77E5-3DF2-4CF1-B95A-636979351E5B'
        Name   = 'Block persistence through WMI event subscription'
        Covers = 'PowerShell persistence via WMI subscriptions'
    }
)

# This script offers Audit and Block only. Warn mode is deliberately not exposed: it is
# unsupported for the LSASS rule above, so a -Warn switch would silently do nothing for
# one of the four and give a misleading impression of coverage.

Write-Host ''
Write-Host 'PowerShell abuse lab - preventive controls' -ForegroundColor White
Write-Host ''

# ======================================================================================
# 1. PowerShell v2 engine
# ======================================================================================

Write-Step 'Checking for the PowerShell v2 engine'

if ($SkipPSv2Removal) {
    Write-Warn 'Skipped (-SkipPSv2Removal)'
}
else {
    try {
        $v2Feature = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction Stop

        if ($v2Feature.State -eq 'Enabled') {
            Write-Warn 'v2 engine is PRESENT. It has no AMSI and no script block logging.'
            Write-Info 'Anything running under it is invisible to detections D2 through D5.'

            if ($PSCmdlet.ShouldProcess('MicrosoftWindowsPowerShellV2Root', 'Disable Windows optional feature')) {
                $result = Disable-WindowsOptionalFeature -Online `
                    -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -ErrorAction Stop

                Write-Ok 'v2 engine removed'
                if ($result.RestartNeeded) { Write-Warn 'Reboot required to finish.' }
            }
        }
        else {
            Write-Ok "v2 engine already absent (state: $($v2Feature.State))"
        }
    }
    catch {
        # Server SKUs expose this through the Windows Feature model instead.
        Write-Warn "Optional-feature check failed: $($_.Exception.Message)"
        Write-Info 'On Windows Server, use: Uninstall-WindowsFeature -Name PowerShell-V2'
    }
}

Write-Host ''

# ======================================================================================
# 2. Defender ASR rules
# ======================================================================================

Write-Step 'Configuring Defender attack surface reduction rules'

$defenderReady = $false

try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop

    # AMRunningMode is absent on older Defender builds, and strict mode turns a missing
    # property into a terminating error rather than $null.
    $runningMode = if ($mpStatus.PSObject.Properties['AMRunningMode']) { $mpStatus.AMRunningMode } else { $null }

    if (-not $runningMode -or $runningMode -eq 'Normal') {
        $defenderReady = $true
        Write-Ok "Defender running mode: $(if ($runningMode) { $runningMode } else { 'unreported, assuming active' })"
    }
    else {
        Write-Warn "Defender running mode is '$runningMode'. ASR rules are ignored unless it is Normal."
        Write-Info 'A third-party AV in active mode puts Defender into passive mode.'
    }
}
catch {
    Write-Warn "Could not query Defender status: $($_.Exception.Message)"
}

if ($defenderReady) {
    if ($Revert) {
        $action = 'Disabled'
    }
    elseif ($Enforce) {
        $action = 'Enabled'      # 'Enabled' IS block mode. There is no 'Block' string value.
    }
    else {
        $action = 'AuditMode'
    }

    Write-Info "Target action: $action"
    Write-Host ''

    foreach ($rule in $AsrRules) {
        Write-Host "    $($rule.Name)" -ForegroundColor White
        Write-Info "  id      : $($rule.Id)"
        Write-Info "  covers  : $($rule.Covers)"

        try {
            if ($PSCmdlet.ShouldProcess($rule.Name, "Set ASR action to $action")) {
                # Add-MpPreference appends. Set-MpPreference would overwrite the entire
                # existing rule list and silently drop rules configured elsewhere.
                Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id `
                    -AttackSurfaceReductionRules_Actions $action -ErrorAction Stop
            }
            Write-Ok "  set to $action"
        }
        catch {
            Write-Warn "  failed: $($_.Exception.Message)"
        }

        Write-Host ''
    }

    if (-not $Enforce -and -not $Revert) {
        Write-Warn 'Rules are in AUDIT mode. They are logging, not blocking.'
        Write-Info 'Review what would have been blocked:'
        Write-Info '  Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |'
        Write-Info '    Where-Object Id -eq 1122'
        Write-Info 'Then re-run with -Enforce.'
    }

    Write-Host ''
    Write-Info 'ASR event IDs in Microsoft-Windows-Windows Defender/Operational:'
    Write-Info '  1121  rule blocked something'
    Write-Info '  1122  rule would have blocked something (audit mode)'
    Write-Info '  1129  user overrode a block in warn mode'
    Write-Info '  (1125 and 1126 are network protection, not ASR - a common mix-up)'
}

Write-Host ''

# ======================================================================================
# 3. AMSI
# ======================================================================================

Write-Step 'Checking AMSI'

try {
    $amsiRegistered = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'

    if ($amsiRegistered) {
        $providers = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue)
        Write-Ok "AMSI provider keys present ($($providers.Count) registered)"
        Write-Info 'AMSI is what raises 4104 events to Level=Warning, which detection D3 uses as corroboration.'
    }
    else {
        Write-Warn 'No AMSI providers registered. D3 loses its Level=Warning signal.'
    }
}
catch {
    Write-Warn "AMSI check failed: $($_.Exception.Message)"
}

Write-Host ''

# ======================================================================================
# 4. Language mode
# ======================================================================================

Write-Step 'Reporting language mode'

$languageMode = $ExecutionContext.SessionState.LanguageMode
Write-Info "Current session language mode: $languageMode"

if ($languageMode -eq 'FullLanguage') {
    Write-Warn 'FullLanguage. Direct .NET and Win32 API access is available, so D4-style injection is possible.'
    Write-Info 'ConstrainedLanguage removes that, but only counts as a control when WDAC or AppLocker'
    Write-Info 'puts it there. Setting __PSLockdownPolicy by hand is trivially reversible and is not'
    Write-Info 'a supported control - do not rely on it.'
}
else {
    Write-Ok "$languageMode - .NET and Win32 API surface is restricted."
}

Write-Host ''

# ======================================================================================
# Execution policy - stated explicitly so nobody assumes it was forgotten
# ======================================================================================

Write-Step 'Execution policy'

$effectivePolicy = Get-ExecutionPolicy
Write-Info "Effective policy: $effectivePolicy"
Write-Warn 'Not changed on purpose. ExecutionPolicy is not a security boundary.'
Write-Info 'Simulation S6 walks straight through it with -ep bypass, and that is by design,'
Write-Info 'not a bug. Treat it as a guard rail against mistakes, never as a control.'

Write-Host ''
Write-Host ("=" * 78) -ForegroundColor DarkGray
Write-Host ' Done. Re-run 02 and 03 to see which techniques are now blocked rather than' -ForegroundColor White
Write-Host ' merely logged.' -ForegroundColor White
Write-Host ("=" * 78) -ForegroundColor DarkGray
Write-Host ''
