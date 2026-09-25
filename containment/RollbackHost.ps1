<#
.SYNOPSIS
    BRDS-PEC Lab Network Rollback Script

.DESCRIPTION
    Re-enables network adapters that were disabled by ContainHost.ps1 during
    a lab detonation test.  Intended to restore connectivity after a VM
    containment experiment without requiring a full snapshot revert.

    Run this AFTER the detonation session, before the next test, or instead
    of reverting a snapshot when you only want to restore the network.

    Mode guard: requires BRDS_LIVE_CONTAINMENT=1 AND -Armed, identical to
    ContainHost.ps1, so a misconfigured environment cannot accidentally
    re-enable adapters mid-test.

.PARAMETER Armed
    Must be explicitly passed.  Requires BRDS_LIVE_CONTAINMENT=1 to execute.

.PARAMETER DryRunOverride
    Force dry-run for CI / testing.

.EXAMPLE
    # After a lab detonation, restore connectivity:
    $env:BRDS_LIVE_CONTAINMENT = "1"
    .\RollbackHost.ps1 -Armed
#>

[CmdletBinding()]
param (
    [switch]$Armed = $false,
    [switch]$DryRunOverride = $false
)

# ── Mode resolution (identical guard to ContainHost.ps1) ─────────────────────
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
    Write-Warning "[BRDS-PEC] Mode: LIVE ROLLBACK (BRDS_LIVE_CONTAINMENT=1 + -Armed verified)"
}

# ── Re-enable disabled adapters ───────────────────────────────────────────────
Write-Host "[BRDS-PEC] Starting network rollback..."

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" }

if ($adapters.Count -eq 0) {
    Write-Host "[BRDS-PEC] No disabled network adapters found — nothing to restore."
    exit 0
}

$restored = @()
foreach ($adapter in $adapters) {
    Write-Host "[BRDS-PEC] Disabled adapter found: $($adapter.Name) ($($adapter.InterfaceDescription))"
    if ($DryRun) {
        Write-Host "[DRY-RUN] Would re-enable adapter: $($adapter.Name)"
    } else {
        Write-Host "[ROLLBACK] Re-enabling network adapter: $($adapter.Name)..."
        try {
            Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
            Write-Host "[ROLLBACK] Adapter $($adapter.Name) re-enabled."
            $restored += $adapter.Name
        } catch {
            Write-Warning "Could not re-enable adapter $($adapter.Name): $_"
        }
    }
}

Write-Host "[BRDS-PEC] Network rollback completed. DryRun=$DryRun RestoredAdapters=$($restored.Count)"
