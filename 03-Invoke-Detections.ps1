#Requires -Version 5.1
<#
.SYNOPSIS
    Seven detections for common PowerShell abuse, each reporting the exact log field and
    substring that fired it.

.DESCRIPTION
    Every finding carries the log name, event ID, the specific EventData field that matched,
    and an excerpt of the matched text, so you can always answer "what made this fire".

    Rules and their evidence source:

      D1  Encoded command            Security 4688 CommandLine        + 4104 ScriptBlockText
      D2  Download cradle into IEX   4104 ScriptBlockText             (two conditions)
      D3  AMSI tampering             4104 ScriptBlockText             + Level=Warning
      D4  In-memory injection        4104 ScriptBlockText
      D5  LSASS credential dumping   4104 ScriptBlockText             + Sysmon 10 GrantedAccess
      D6  Suspicious launch flags    Security 4688 CommandLine        + classic 400 HostApplication
      D7  PowerShell v2 downgrade    Windows PowerShell 400 EngineVersion

    Emits finding objects to the pipeline, so:
        $f = .\03-Invoke-Detections.ps1 -SinceMinutes 30
        $f | Export-Csv findings.csv -NoTypeInformation

.PARAMETER SinceMinutes
    How far back to look. Default 60.

.PARAMETER IncludeLabFiles
    By default, 4104 events whose Path is one of this lab's own .ps1 files are ignored.
    Those files contain every indicator as literal text, so without the filter each rule
    fires on the lab itself and drowns the real hits.

    Turn this on to see that happen. It is worth seeing once: security tooling routinely
    trips content-based rules, and this is the smallest honest example of it.

.PARAMETER Quiet
    Suppress the console report and emit objects only.

.EXAMPLE
    .\03-Invoke-Detections.ps1 -SinceMinutes 10

.EXAMPLE
    .\03-Invoke-Detections.ps1 | Where-Object Severity -eq 'High' | Format-List

.NOTES
    Reading the Security log requires an elevated session. Without it, D1 and D6 fall back
    to their PowerShell-log evidence and D7 is unaffected.
#>
[CmdletBinding()]
param(
    [int]    $SinceMinutes = 60,
    [switch] $IncludeLabFiles,
    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Since    = (Get-Date).AddMinutes(-[Math]::Abs($SinceMinutes))
$Findings = [System.Collections.Generic.List[object]]::new()

$LabFileNames = @(
    '01-Enable-Logging.ps1',
    '02-Invoke-Simulations.ps1',
    '03-Invoke-Detections.ps1',
    '04-Enable-Blocking.ps1'
)

# ======================================================================================
# Helpers
# ======================================================================================

function Get-LabEvent {
    <#
        Get-WinEvent errors when a filter matches nothing, which is the normal case for
        most rules. Swallow that and return an empty array so callers can just enumerate.
    #>
    param([Parameter(Mandatory)] [hashtable] $Filter)

    try {
        $events = Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop
        # The leading comma stops the pipeline unrolling the array. Without it an empty
        # result is emitted as nothing at all, the caller's variable becomes $null, and
        # @($null) is a ONE-element array containing $null - which then feeds a bogus
        # iteration into every rule loop and inflates the evidence counts.
        return , @($events)
    }
    catch {
        return , @()
    }
}

function Get-EventDataMap {
    <#
        Flattens <EventData><Data Name="X">v</Data></EventData> into a hashtable.
        Unnamed Data elements (the classic PowerShell log uses these) are keyed Data0, Data1...
    #>
    param([Parameter(Mandatory)] $Event)

    $map = @{}

    try {
        $xml = [xml]$Event.ToXml()

        if (-not $xml.Event.PSObject.Properties['EventData']) { return $map }
        if (-not $xml.Event.EventData)                        { return $map }

        $i = 0

        foreach ($node in @($xml.Event.EventData.Data)) {
            if ($null -eq $node) { $i++; continue }

            if ($node -is [string]) {
                # Elements with no attributes come back from the XML adapter as bare
                # strings. The classic Windows PowerShell log does this.
                $map["Data$i"] = $node
            }
            else {
                # GetAttribute rather than $node.Name: 'Name' is also an intrinsic
                # XmlElement property, so dotted access is ambiguous and can hand back
                # the element name 'Data' instead of the attribute value.
                $attribute = ''
                try { $attribute = [string]$node.GetAttribute('Name') } catch { }

                if ($attribute) { $map[$attribute] = [string]$node.InnerText }
                else            { $map["Data$i"]   = [string]$node.InnerText }
            }

            $i++
        }
    }
    catch {
        # Malformed or inaccessible event - return whatever we managed to collect.
    }

    return $map
}

function Get-Field {
    param([hashtable] $Map, [string] $Name, [string] $Default = '')
    if ($Map.ContainsKey($Name) -and $Map[$Name]) { return [string]$Map[$Name] }
    return $Default
}

function Get-MatchExcerpt {
    <#
        Returns the matched text plus surrounding context, whitespace-collapsed. This is
        the "exact log evidence" shown in the report - not a paraphrase of the rule, but
        the bytes out of the event that satisfied it.
    #>
    param(
        [string] $Text,
        [string] $Pattern,
        [int]    $Pad = 55
    )

    if ([string]::IsNullOrEmpty($Text)) { return '' }

    $match = [regex]::Match($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $match.Success) { return '' }

    $start = [Math]::Max(0, $match.Index - $Pad)
    $end   = [Math]::Min($Text.Length, $match.Index + $match.Length + $Pad)
    $slice = $Text.Substring($start, $end - $start) -replace '\s+', ' '

    $prefix = if ($start -gt 0)            { '...' } else { '' }
    $suffix = if ($end   -lt $Text.Length) { '...' } else { '' }

    return "$prefix$($slice.Trim())$suffix"
}

function Resolve-EventUser {
    param($Event, [hashtable] $Map)

    $name = Get-Field $Map 'SubjectUserName'
    if ($name) {
        $domain = Get-Field $Map 'SubjectDomainName'
        if ($domain) { return "$domain\$name" }
        return $name
    }

    if ($Event.UserId) {
        try   { return $Event.UserId.Translate([System.Security.Principal.NTAccount]).Value }
        catch { return $Event.UserId.Value }
    }

    return ''
}

function Add-Finding {
    param(
        [Parameter(Mandatory)] [string] $RuleId,
        [Parameter(Mandatory)] [string] $RuleName,
        [Parameter(Mandatory)] [string] $Technique,
        [Parameter(Mandatory)] [ValidateSet('High', 'Medium', 'Low')] [string] $Severity,
        [Parameter(Mandatory)] $Event,
        [Parameter(Mandatory)] [string] $EvidenceField,
        [Parameter(Mandatory)] [string] $Evidence,
        [string] $Why = '',
        [hashtable] $Map = @{}
    )

    $Findings.Add([pscustomobject][ordered]@{
        RuleId        = $RuleId
        RuleName      = $RuleName
        Technique     = $Technique
        Severity      = $Severity
        TimeCreated   = $Event.TimeCreated
        LogName       = $Event.LogName
        EventId       = $Event.Id
        Level         = $Event.LevelDisplayName
        Computer      = $Event.MachineName
        User          = Resolve-EventUser -Event $Event -Map $Map
        EvidenceField = $EvidenceField
        Evidence      = $Evidence
        Why           = $Why
        RecordId      = $Event.RecordId
    })
}

function Test-IsElevated {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ======================================================================================
# Collect evidence sources once
# ======================================================================================

$isElevated = Test-IsElevated

if (-not $Quiet) {
    Write-Host ''
    Write-Host 'PowerShell abuse lab - detections' -ForegroundColor White
    Write-Host ("Window: {0:yyyy-MM-dd HH:mm:ss} to now ({1} min)" -f $Since, $SinceMinutes) -ForegroundColor DarkGray
    if (-not $isElevated) {
        Write-Host 'Not elevated - Security 4688 evidence unavailable, D1/D6 will use PowerShell-log evidence only.' -ForegroundColor Yellow
    }
    Write-Host ''
}

# --- 4104 script blocks ---------------------------------------------------------------

$raw4104 = Get-LabEvent -Filter @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = $Since
}

$ScriptBlocks = foreach ($event in $raw4104) {
    $map  = Get-EventDataMap -Event $event
    $path = Get-Field $map 'Path'

    if (-not $IncludeLabFiles -and $path) {
        $leaf = Split-Path -Path $path -Leaf
        if ($LabFileNames -contains $leaf) { continue }
    }

    [pscustomobject]@{
        Event = $event
        Map   = $map
        Text  = Get-Field $map 'ScriptBlockText'
        Path  = $path
    }
}

# Piping through Where-Object is what makes this a genuinely empty array when the foreach
# above produced nothing. A bare @($ScriptBlocks) on a $null would yield Count = 1.
$ScriptBlocks = @($ScriptBlocks | Where-Object { $null -ne $_ })

# --- 4688 process creations -----------------------------------------------------------

$ProcessEvents = @()

if ($isElevated) {
    $raw4688 = Get-LabEvent -Filter @{
        LogName   = 'Security'
        Id        = 4688
        StartTime = $Since
    }

    $ProcessEvents = foreach ($event in $raw4688) {
        $map     = Get-EventDataMap -Event $event
        $cmdLine = Get-Field $map 'CommandLine'
        $image   = Get-Field $map 'NewProcessName'

        if (-not $cmdLine) { continue }

        [pscustomobject]@{
            Event       = $event
            Map         = $map
            CommandLine = $cmdLine
            Image       = $image
            IsPowerShell = ($image -match '(?i)\\(powershell(_ise)?|pwsh)\.exe$') -or
                           ($cmdLine -match '(?i)\b(powershell(_ise)?|pwsh)(\.exe)?\b')
        }
    }

    $ProcessEvents = @($ProcessEvents | Where-Object { $null -ne $_ })
}

# --- Classic Windows PowerShell log 400 -----------------------------------------------

$EngineStarts = Get-LabEvent -Filter @{
    LogName   = 'Windows PowerShell'
    Id        = 400
    StartTime = $Since
}

# --- Sysmon 10 process access (optional) ----------------------------------------------

$SysmonAvailable = $null -ne (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
$ProcessAccess   = @()

if ($SysmonAvailable) {
    $ProcessAccess = Get-LabEvent -Filter @{
        LogName   = 'Microsoft-Windows-Sysmon/Operational'
        Id        = 10
        StartTime = $Since
    }
}

if (-not $Quiet) {
    Write-Host ("Evidence collected: {0} script blocks (4104), {1} process creations (4688), {2} engine starts (400), {3} process access (Sysmon 10)" -f `
        $ScriptBlocks.Count, $ProcessEvents.Count, @($EngineStarts).Count, @($ProcessAccess).Count) -ForegroundColor DarkGray
    Write-Host ''
}

# ======================================================================================
# D1 - Base64 encoded command
# ======================================================================================
# Evidence: Security 4688 CommandLine, an -e* abbreviation followed by a long base64 blob.
# The blob length requirement is what keeps this off -ExecutionPolicy Bypass, which also
# starts with -e but is followed by a short word.

$D1_CommandLine = '(?i)(?:^|\s)-e[a-z]*\s+[A-Za-z0-9+/=]{20,}'
$D1_ScriptBlock = '(?i)FromBase64String'

foreach ($proc in $ProcessEvents) {
    if (-not $proc.IsPowerShell) { continue }

    $excerpt = Get-MatchExcerpt -Text $proc.CommandLine -Pattern $D1_CommandLine
    if (-not $excerpt) { continue }

    Add-Finding -RuleId 'D1' -RuleName 'Base64 encoded command' -Technique 'T1027.010 / T1059.001' `
        -Severity 'High' -Event $proc.Event -Map $proc.Map `
        -EvidenceField 'CommandLine' -Evidence $excerpt `
        -Why 'PowerShell launched with an -EncodedCommand abbreviation and a base64 payload.'
}

foreach ($block in $ScriptBlocks) {
    $excerpt = Get-MatchExcerpt -Text $block.Text -Pattern $D1_ScriptBlock
    if (-not $excerpt) { continue }

    Add-Finding -RuleId 'D1' -RuleName 'Base64 decoding in script block' -Technique 'T1027.010' `
        -Severity 'Medium' -Event $block.Event -Map $block.Map `
        -EvidenceField 'ScriptBlockText' -Evidence $excerpt `
        -Why 'Script block decodes base64 at runtime. Common in loaders, also used legitimately.'
}

# ======================================================================================
# D2 - Download cradle into Invoke-Expression
# ======================================================================================
# Evidence: 4104 ScriptBlockText satisfying BOTH conditions. Either alone is ordinary
# admin scripting; the pair - fetch remote content, then execute it as code - is the
# cradle pattern and is rare in benign scripts.

$D2_Download = '(?i)(DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|Start-BitsTransfer)'
$D2_Execute  = '(?i)(Invoke-Expression|\bIEX\b)'

foreach ($block in $ScriptBlocks) {
    $downloadHit = Get-MatchExcerpt -Text $block.Text -Pattern $D2_Download
    if (-not $downloadHit) { continue }

    $executeHit = Get-MatchExcerpt -Text $block.Text -Pattern $D2_Execute
    if (-not $executeHit) { continue }

    Add-Finding -RuleId 'D2' -RuleName 'Download cradle into Invoke-Expression' -Technique 'T1059.001 / T1105' `
        -Severity 'High' -Event $block.Event -Map $block.Map `
        -EvidenceField 'ScriptBlockText' -Evidence "$downloadHit  ||  $executeHit" `
        -Why 'Same script block both retrieves remote content and executes it as code.'
}

# ======================================================================================
# D3 - AMSI tampering
# ======================================================================================
# Evidence: 4104 ScriptBlockText naming AMSI internals. Nothing legitimate reaches into
# AmsiUtils, so this is a single-condition rule with a very low false positive rate.
# A Level of Warning on the same event is corroboration: AMSI flagged the content itself.

$D3_Pattern = '(?i)(AmsiUtils|amsiInitFailed|AmsiScanBuffer|AmsiOpenSession|AmsiContext)'

foreach ($block in $ScriptBlocks) {
    $excerpt = Get-MatchExcerpt -Text $block.Text -Pattern $D3_Pattern
    if (-not $excerpt) { continue }

    $why = 'Script block references AMSI internals. No legitimate administrative script does this.'
    if ($block.Event.LevelDisplayName -eq 'Warning') {
        $why += ' Event Level is Warning, meaning AMSI independently flagged this content.'
    }

    Add-Finding -RuleId 'D3' -RuleName 'AMSI tampering indicators' -Technique 'T1562.001' `
        -Severity 'High' -Event $block.Event -Map $block.Map `
        -EvidenceField 'ScriptBlockText' -Evidence $excerpt -Why $why
}

# ======================================================================================
# D4 - In-memory injection API surface
# ======================================================================================
# Evidence: 4104 ScriptBlockText naming the Win32 allocate/write/execute trio or the
# reflective loading APIs. Legitimate use exists (some installers, some monitoring tools)
# so this is Medium unless paired with another rule on the same host.

$D4_Pattern = '(?i)(VirtualAlloc(Ex)?|WriteProcessMemory|CreateRemoteThread(Ex)?|NtCreateThreadEx|QueueUserAPC|GetDelegateForFunctionPointer|\[(System\.)?Reflection\.Assembly\]::Load)'

foreach ($block in $ScriptBlocks) {
    $excerpt = Get-MatchExcerpt -Text $block.Text -Pattern $D4_Pattern
    if (-not $excerpt) { continue }

    Add-Finding -RuleId 'D4' -RuleName 'In-memory injection API surface' -Technique 'T1055 / T1620' `
        -Severity 'Medium' -Event $block.Event -Map $block.Map `
        -EvidenceField 'ScriptBlockText' -Evidence $excerpt `
        -Why 'Script block names memory allocation, remote thread or reflective load APIs.'
}

# ======================================================================================
# D5 - LSASS credential dumping
# ======================================================================================
# Two independent evidence paths. The 4104 path catches the command text. The Sysmon 10
# path is the higher-fidelity one because it observes the actual handle open against
# lsass.exe, which text matching can never prove.

$D5_ScriptText = '(?i)(MiniDumpWriteDump|comsvcs\.dll\s*,?\s*MiniDump|Out-Minidump|lsass\.dmp|procdump[^\r\n]{0,40}lsass)'

foreach ($block in $ScriptBlocks) {
    $excerpt = Get-MatchExcerpt -Text $block.Text -Pattern $D5_ScriptText
    if (-not $excerpt) { continue }

    Add-Finding -RuleId 'D5' -RuleName 'LSASS dump tradecraft in script' -Technique 'T1003.001' `
        -Severity 'High' -Event $block.Event -Map $block.Map `
        -EvidenceField 'ScriptBlockText' -Evidence $excerpt `
        -Why 'Script block contains LSASS memory dumping command text.'
}

# GrantedAccess masks that include PROCESS_VM_READ against lsass.exe. 0x1010 and 0x1410
# are the classic dumper masks; 0x1FFFFF is PROCESS_ALL_ACCESS.
$D5_AccessMasks = @('0x1010', '0x1410', '0x1438', '0x143a', '0x1f1fff', '0x1fffff')

foreach ($event in $ProcessAccess) {
    $map         = Get-EventDataMap -Event $event
    $targetImage = Get-Field $map 'TargetImage'
    $access      = (Get-Field $map 'GrantedAccess').ToLower()
    $sourceImage = Get-Field $map 'SourceImage'

    if ($targetImage -notmatch '(?i)\\lsass\.exe$') { continue }
    if ($D5_AccessMasks -notcontains $access)       { continue }

    Add-Finding -RuleId 'D5' -RuleName 'LSASS handle opened for memory read' -Technique 'T1003.001' `
        -Severity 'High' -Event $event -Map $map `
        -EvidenceField 'GrantedAccess' -Evidence "SourceImage=$sourceImage GrantedAccess=$access TargetImage=$targetImage" `
        -Why 'A process opened lsass.exe with an access mask that permits reading its memory.'
}

# ======================================================================================
# D6 - Suspicious launch flag combination
# ======================================================================================
# Evidence: Security 4688 CommandLine, or the HostApplication field inside classic
# event 400 when 4688 command line auditing is unavailable.
#
# Any one of these flags is normal. Scheduled tasks use -NonInteractive, installers use
# -ExecutionPolicy Bypass. The rule requires TWO DIFFERENT families, because stacking them
# is what operator tooling and malicious shortcuts do and what routine automation does not.

$D6_Families = [ordered]@{
    'NoProfile'      = '(?i)(?:^|\s)-nop(rofile)?\b'
    'HiddenWindow'   = '(?i)-w(indowstyle)?\s+hidden\b'
    'BypassPolicy'   = '(?i)-e[a-z]*\s+(bypass|unrestricted)\b'
    'NonInteractive' = '(?i)(?:^|\s)-noni(nteractive)?\b'
    'EncodedCommand' = '(?i)(?:^|\s)-e[a-z]*\s+[A-Za-z0-9+/=]{20,}'
}

function Get-FlagFamilyHits {
    param([string] $CommandLine)

    $hits = [ordered]@{}

    foreach ($family in $D6_Families.GetEnumerator()) {
        $excerpt = Get-MatchExcerpt -Text $CommandLine -Pattern $family.Value -Pad 12
        if ($excerpt) { $hits[$family.Key] = $excerpt }
    }

    return $hits
}

foreach ($proc in $ProcessEvents) {
    if (-not $proc.IsPowerShell) { continue }

    $hits = Get-FlagFamilyHits -CommandLine $proc.CommandLine
    if ($hits.Count -lt 2) { continue }

    Add-Finding -RuleId 'D6' -RuleName 'Suspicious launch flag combination' -Technique 'T1059.001 / T1564.003' `
        -Severity 'High' -Event $proc.Event -Map $proc.Map `
        -EvidenceField 'CommandLine' `
        -Evidence ("{0} -- {1}" -f ($hits.Keys -join ' + '), (Get-MatchExcerpt -Text $proc.CommandLine -Pattern '(?i)(powershell|pwsh)' -Pad 90)) `
        -Why ("{0} stacked flag families on one PowerShell invocation." -f $hits.Count)
}

# Fallback path: classic event 400 carries the launching command line in HostApplication,
# which survives even when 4688 command line auditing was never turned on.
foreach ($event in $EngineStarts) {
    $message = $event.Message
    if (-not $message) { continue }

    $hostMatch = [regex]::Match($message, '(?im)^\s*HostApplication\s*=\s*(.+)$')
    if (-not $hostMatch.Success) { continue }

    $hostApp = $hostMatch.Groups[1].Value.Trim()
    $hits    = Get-FlagFamilyHits -CommandLine $hostApp
    if ($hits.Count -lt 2) { continue }

    Add-Finding -RuleId 'D6' -RuleName 'Suspicious launch flags (via HostApplication)' -Technique 'T1059.001 / T1564.003' `
        -Severity 'Medium' -Event $event -Map (Get-EventDataMap -Event $event) `
        -EvidenceField 'HostApplication' -Evidence ("{0} -- {1}" -f ($hits.Keys -join ' + '), $hostApp) `
        -Why 'Same flag stacking, recovered from the classic PowerShell engine start event.'
}

# ======================================================================================
# D7 - PowerShell v2 engine downgrade
# ======================================================================================
# Evidence: classic event 400, EngineVersion=2.0.
#
# This one matters out of proportion to its simplicity. The v2 engine predates AMSI and
# Script Block Logging, so an attacker who downgrades to it turns off D2 through D5
# wholesale. The absence of 4104 events is not something you can alert on directly, but
# EngineVersion=2.0 in the classic log is, and the classic log still records it.

$D7_Pattern = '(?im)^\s*EngineVersion\s*=\s*2\.0\s*$'

foreach ($event in $EngineStarts) {
    $message = $event.Message
    if (-not $message) { continue }

    $excerpt = Get-MatchExcerpt -Text $message -Pattern $D7_Pattern -Pad 30
    if (-not $excerpt) { continue }

    Add-Finding -RuleId 'D7' -RuleName 'PowerShell v2 engine downgrade' -Technique 'T1562.001' `
        -Severity 'High' -Event $event -Map (Get-EventDataMap -Event $event) `
        -EvidenceField 'EngineVersion' -Evidence $excerpt `
        -Why 'Engine started under v2, which has no AMSI and no script block logging. Blinds D2-D5.'
}

# ======================================================================================
# Report
# ======================================================================================

if (-not $Quiet) {
    $allRules = [ordered]@{
        'D1' = 'Base64 encoded command'
        'D2' = 'Download cradle into Invoke-Expression'
        'D3' = 'AMSI tampering indicators'
        'D4' = 'In-memory injection API surface'
        'D5' = 'LSASS credential dumping'
        'D6' = 'Suspicious launch flag combination'
        'D7' = 'PowerShell v2 engine downgrade'
    }

    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host ' RULE COVERAGE' -ForegroundColor White
    Write-Host ("=" * 78) -ForegroundColor DarkGray

    foreach ($rule in $allRules.GetEnumerator()) {
        $count = @($Findings | Where-Object RuleId -eq $rule.Key).Count

        if ($count -gt 0) {
            Write-Host ("  {0}  {1,-42} {2} hit(s)" -f $rule.Key, $rule.Value, $count) -ForegroundColor Red
        }
        else {
            Write-Host ("  {0}  {1,-42} no hits" -f $rule.Key, $rule.Value) -ForegroundColor DarkGray
        }
    }

    if (-not $SysmonAvailable) {
        Write-Host ''
        Write-Host '  Sysmon not installed - the D5 ProcessAccess branch was skipped.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host " FINDINGS ($($Findings.Count))" -ForegroundColor White
    Write-Host ("=" * 78) -ForegroundColor DarkGray

    if ($Findings.Count -eq 0) {
        Write-Host ''
        Write-Host '  Nothing matched in this window.' -ForegroundColor Green
        Write-Host '  If you just ran the simulations, widen it: -SinceMinutes 10' -ForegroundColor DarkGray
        Write-Host '  If it stays empty, Script Block Logging was probably enabled after this session started.' -ForegroundColor DarkGray
        Write-Host ''
    }
    else {
        foreach ($finding in ($Findings | Sort-Object RuleId, TimeCreated)) {
            $color = switch ($finding.Severity) {
                'High'   { 'Red' }
                'Medium' { 'Yellow' }
                default  { 'Gray' }
            }

            Write-Host ''
            Write-Host ("  [{0}] {1}" -f $finding.RuleId, $finding.RuleName) -ForegroundColor $color
            Write-Host ("      technique : {0}   severity: {1}" -f $finding.Technique, $finding.Severity) -ForegroundColor DarkGray
            Write-Host ("      when      : {0:yyyy-MM-dd HH:mm:ss}   user: {1}" -f $finding.TimeCreated, $finding.User) -ForegroundColor DarkGray
            Write-Host ("      source    : {0}  Event ID {1}  (record {2})" -f $finding.LogName, $finding.EventId, $finding.RecordId) -ForegroundColor DarkGray
            Write-Host ("      field     : {0}" -f $finding.EvidenceField) -ForegroundColor Cyan
            Write-Host ("      evidence  : {0}" -f $finding.Evidence) -ForegroundColor White
            Write-Host ("      why       : {0}" -f $finding.Why) -ForegroundColor DarkGray
        }

        Write-Host ''
    }

    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host ''
}

$Findings
