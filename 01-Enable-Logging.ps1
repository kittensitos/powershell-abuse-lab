#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Turns on the PowerShell and process-creation telemetry that the lab detections read.

.DESCRIPTION
    Configures four evidence sources, each of which maps to specific detections in
    DETECTIONS.md:

      1. Script Block Logging  -> Microsoft-Windows-PowerShell/Operational, Event ID 4104
      2. Module Logging        -> Microsoft-Windows-PowerShell/Operational, Event ID 4103
      3. Transcription         -> flat text files under -TranscriptPath
      4. Process command line  -> Security, Event ID 4688 (CommandLine field)

    Script Block Logging is the load-bearing one. It records the *text* of every script
    block at compile time, before and independently of whether that block runs. That is
    what makes 02-Invoke-Simulations.ps1 both realistic and safe.

    Everything is written under the Policies keys, which is where Group Policy would put
    it. If real GPO also manages these settings it will overwrite what this script does at
    the next policy refresh; that is expected and is why the lab is for test hosts.

.PARAMETER TranscriptPath
    Directory for transcript output. Created if missing.

.PARAMETER SkipTranscription
    Leave transcription off. Transcripts are the noisiest and most disk-hungry source and
    none of the seven lab detections require them.

.PARAMETER Revert
    Remove the settings this script applies and restore the prior audit policy for
    Process Creation. Use this to clean up a test host.

.EXAMPLE
    .\01-Enable-Logging.ps1

.EXAMPLE
    .\01-Enable-Logging.ps1 -Revert

.NOTES
    Run on a disposable test host or VM. Requires an elevated session.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $TranscriptPath = 'C:\PSLab\Transcripts',
    [switch] $SkipTranscription,
    [switch] $Revert
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PSRoot         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$ScriptBlockKey = Join-Path $PSRoot 'ScriptBlockLogging'
$ModuleKey      = Join-Path $PSRoot 'ModuleLogging'
$ModuleNamesKey = Join-Path $ModuleKey 'ModuleNames'
$TranscriptKey  = Join-Path $PSRoot 'Transcription'
$AuditKey       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'

function Write-Step {
    param([string] $Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string] $Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string] $Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Set-PolicyValue {
    <#
        Creates the key if needed and sets one value. Kept separate so the -Revert path
        and the apply path stay symmetrical and readable.
    #>
    # SupportsShouldProcess must be declared here too. These helpers are advanced functions
    # in their own right, so they get their own $PSCmdlet rather than inheriting the
    # script's, and calling ShouldProcess without declaring support for it is not valid.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] $Value,
        [ValidateSet('DWord', 'String')] [string] $Type = 'DWord'
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, 'Create registry key')) {
            New-Item -Path $Path -Force | Out-Null
        }
    }

    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to '$Value'")) {
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
}

function Get-PolicyValue {
    <#
        Returns the value or $null. Needed because Set-StrictMode -Version Latest makes
        property access on a missing key an error rather than a quiet $null.
    #>
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    if (-not $item.PSObject.Properties[$Name]) { return $null }

    return $item.$Name
}

function Remove-PolicyKey {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)] [string] $Path)

    if (Test-Path -LiteralPath $Path) {
        if ($PSCmdlet.ShouldProcess($Path, 'Remove registry key')) {
            Remove-Item -LiteralPath $Path -Recurse -Force
            Write-Ok "Removed $Path"
        }
    }
}

# --------------------------------------------------------------------------------------
# Revert
# --------------------------------------------------------------------------------------

if ($Revert) {
    Write-Step 'Reverting lab logging configuration'

    Remove-PolicyKey -Path $ScriptBlockKey
    Remove-PolicyKey -Path $ModuleKey
    Remove-PolicyKey -Path $TranscriptKey

    if (Test-Path -LiteralPath $AuditKey) {
        if ($PSCmdlet.ShouldProcess("$AuditKey\ProcessCreationIncludeCmdLine_Enabled", 'Remove registry value')) {
            Remove-ItemProperty -LiteralPath $AuditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' `
                -Force -ErrorAction SilentlyContinue
            Write-Ok 'Cleared ProcessCreationIncludeCmdLine_Enabled'
        }
    }

    if ($PSCmdlet.ShouldProcess('Process Creation', 'Disable success auditing')) {
        auditpol.exe /set /subcategory:"Process Creation" /success:disable | Out-Null
        Write-Ok 'Disabled Process Creation success auditing'
    }

    Write-Host ''
    Write-Warn 'Transcript files were left in place. Delete them yourself if you want them gone.'
    Write-Host ''
    return
}

# --------------------------------------------------------------------------------------
# 1. Script Block Logging  ->  Event ID 4104
# --------------------------------------------------------------------------------------

Write-Step 'Enabling Script Block Logging (evidence for detections D2, D3, D4, D5)'

Set-PolicyValue -Path $ScriptBlockKey -Name 'EnableScriptBlockLogging' -Value 1

# EnableScriptBlockInvocationLogging is deliberately left off. It adds a start/stop event
# for every single block invocation and will bury the lab in noise. Nothing here needs it.
Set-PolicyValue -Path $ScriptBlockKey -Name 'EnableScriptBlockInvocationLogging' -Value 0

Write-Ok 'Script Block Logging on -> Microsoft-Windows-PowerShell/Operational 4104'

# --------------------------------------------------------------------------------------
# 2. Module Logging  ->  Event ID 4103
# --------------------------------------------------------------------------------------

Write-Step 'Enabling Module Logging (corroborating evidence, Event ID 4103)'

Set-PolicyValue -Path $ModuleKey      -Name 'EnableModuleLogging' -Value 1
Set-PolicyValue -Path $ModuleNamesKey -Name '*'                   -Value '*' -Type String

Write-Ok 'Module Logging on for all modules -> Microsoft-Windows-PowerShell/Operational 4103'

# --------------------------------------------------------------------------------------
# 3. Transcription  ->  flat files
# --------------------------------------------------------------------------------------

if ($SkipTranscription) {
    Write-Warn 'Skipping transcription (-SkipTranscription)'
}
else {
    Write-Step "Enabling transcription to $TranscriptPath"

    if (-not (Test-Path -LiteralPath $TranscriptPath)) {
        New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null
    }

    Set-PolicyValue -Path $TranscriptKey -Name 'EnableTranscripting'    -Value 1
    Set-PolicyValue -Path $TranscriptKey -Name 'EnableInvocationHeader' -Value 1
    Set-PolicyValue -Path $TranscriptKey -Name 'OutputDirectory'        -Value $TranscriptPath -Type String

    Write-Ok "Transcription on -> $TranscriptPath"
    Write-Warn 'Transcripts capture command output, which can include secrets. Protect the ACL on that directory.'
}

# --------------------------------------------------------------------------------------
# 4. Process creation with command line  ->  Security Event ID 4688
# --------------------------------------------------------------------------------------

Write-Step 'Enabling process creation auditing with command line (evidence for D1, D6)'

Set-PolicyValue -Path $AuditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1

if ($PSCmdlet.ShouldProcess('Process Creation', 'Enable success auditing')) {
    auditpol.exe /set /subcategory:"Process Creation" /success:enable | Out-Null
    Write-Ok 'Process creation auditing on -> Security 4688 with CommandLine populated'
}

Write-Warn 'Without ProcessCreationIncludeCmdLine_Enabled, 4688 records the image path but not the arguments, and D1/D6 go blind.'

# --------------------------------------------------------------------------------------
# Raise the Operational log size so the lab does not roll its own evidence away
# --------------------------------------------------------------------------------------

Write-Step 'Sizing the PowerShell Operational log to 256 MB'

# wevtutil signals failure through its exit code, not an exception, so a try/catch alone
# would report success on every run. Relaxing the preference around the redirect keeps
# stderr lines from being promoted to a terminating error on PowerShell 7; the finally
# block restores it even if wevtutil.exe is missing entirely.
$savedPreference = $ErrorActionPreference
$resizeOutput    = $null
$resizeExit      = -1

try {
    $ErrorActionPreference = 'SilentlyContinue'
    $resizeOutput = & wevtutil.exe sl 'Microsoft-Windows-PowerShell/Operational' /ms:268435456 2>&1
    $resizeExit   = $LASTEXITCODE
}
catch {
    $resizeOutput = $_.Exception.Message
}
finally {
    $ErrorActionPreference = $savedPreference
}

if ($resizeExit -eq 0) {
    Write-Ok 'Log size set'
}
else {
    Write-Warn "Could not resize the log (exit $resizeExit): $(($resizeOutput | Out-String).Trim())"
    Write-Warn 'Not fatal. A small log just means evidence rolls away sooner.'
}

# --------------------------------------------------------------------------------------
# Verify
# --------------------------------------------------------------------------------------

Write-Host ''
Write-Step 'Verification'

$checks = [ordered]@{
    'Script Block Logging (4104)' = (Get-PolicyValue -Path $ScriptBlockKey -Name 'EnableScriptBlockLogging') -eq 1
    'Module Logging (4103)'       = (Get-PolicyValue -Path $ModuleKey -Name 'EnableModuleLogging') -eq 1
    'Transcription'               = $SkipTranscription.IsPresent -or ((Get-PolicyValue -Path $TranscriptKey -Name 'EnableTranscripting') -eq 1)
    '4688 CommandLine'            = (Get-PolicyValue -Path $AuditKey -Name 'ProcessCreationIncludeCmdLine_Enabled') -eq 1
}

foreach ($check in $checks.GetEnumerator()) {
    if ($check.Value) { Write-Ok  $check.Key }
    else              { Write-Warn "$($check.Key) -- NOT enabled" }
}

$auditState = auditpol.exe /get /subcategory:"Process Creation"
Write-Host ''
Write-Host ($auditState | Out-String).Trim() -ForegroundColor DarkGray

Write-Host ''
Write-Warn 'Open a NEW PowerShell session before running 02-Invoke-Simulations.ps1.'
Write-Warn 'The current session already read the old policy and will not emit 4104 events.'
Write-Host ''
