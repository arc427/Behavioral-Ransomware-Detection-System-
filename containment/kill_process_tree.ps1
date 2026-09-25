<#
.SYNOPSIS
    BRDS-PEC Process Tree Termination Script

.DESCRIPTION
    Recursively terminates the target process and all its descendants.
    Refuses to touch a hardcoded list of critical Windows system processes.

    Mode resolution is identical to ContainHost.ps1:
      BRDS_LIVE_CONTAINMENT=1 AND -Armed => live kill
      Anything else               => dry-run (log only)

.PARAMETER ParentPid
    PID of the root ransomware process to collapse.

.PARAMETER Armed
    Must be passed only after the caller (trigger_daemon.py) has verified
    the HMAC-signed arm token AND BRDS_LIVE_CONTAINMENT=1 is set.

.PARAMETER DryRunOverride
    Force dry-run regardless of other flags.  Used in CI / unit tests.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [int]$ParentPid,
    [switch]$Armed = $false,
    [Alias("DryRun")]
    [switch]$DryRunOverride = $false
)

# ── Mode resolution ───────────────────────────────────────────────────────────
$liveContainmentEnv = [System.Environment]::GetEnvironmentVariable("BRDS_LIVE_CONTAINMENT")
$envArmed = ($liveContainmentEnv -eq "1")

if ($DryRunOverride.IsPresent) {
    $DryRun = $true
    Write-Host "[BRDS-PEC] Mode: DRY-RUN (DryRunOverride flag set)"
} elseif (-not $Armed.IsPresent) {
    $DryRun = $true
    Write-Host "[BRDS-PEC] Mode: DRY-RUN (-Armed not passed by caller)"
} elseif (-not $envArmed) {
    $DryRun = $true
    Write-Warning "[BRDS-PEC] Mode: DRY-RUN (BRDS_LIVE_CONTAINMENT != 1 in environment)"
} else {
    $DryRun = $false
    Write-Warning "[BRDS-PEC] Mode: LIVE CONTAINMENT (BRDS_LIVE_CONTAINMENT=1 + -Armed verified)"
}

# ── Protected critical Windows system processes (never terminate) ─────────────
$PROTECTED_PROCESSES = @(
    'lsass','csrss','smss','wininit','winlogon',
    'services','system','svchost','explorer','spoolsv','dwm'
)

# ── Recursive tree collapse ───────────────────────────────────────────────────
function Stop-ProcessTree {
    param ([int]$targetPid)

    $children = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Where-Object { $_.ParentProcessId -eq $targetPid }

    foreach ($child in $children) {
        Stop-ProcessTree -targetPid $child.ProcessId
    }

    $procName = "Unknown"
    try {
        $p = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
        if ($p) { $procName = $p.Name }
    } catch {}

    if ($PROTECTED_PROCESSES -contains $procName.ToLower()) {
        Write-Host "[SAFETY] Refusing to terminate protected system process: $procName (PID: $targetPid)"
        return
    }

    if ($DryRun) {
        Write-Host "[DRY-RUN] Would terminate process: $procName (PID: $targetPid)"
    } else {
        Write-Host "[CONTAINMENT] Terminating: $procName (PID: $targetPid)..."
        try {
            Stop-Process -Id $targetPid -Force -ErrorAction Stop
            Write-Host "[CONTAINMENT] Process $targetPid ($procName) terminated."
        } catch {
            Write-Warning "Could not terminate process ${targetPid}: $_"
        }
    }
}

Write-Host "[BRDS-PEC] Initiating process tree collapse for PID: $ParentPid (DryRun=$DryRun)..."
Stop-ProcessTree -targetPid $ParentPid
Write-Host "[BRDS-PEC] Process tree collapse completed."
