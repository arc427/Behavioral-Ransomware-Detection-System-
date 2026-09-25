<#
.SYNOPSIS
    BRDS-PEC Host Network Isolation Script

.DESCRIPTION
    Disables all active network adapters to isolate a compromised host.
    Execution mode is determined by the BRDS_LIVE_CONTAINMENT environment
    variable AND a separately verified HMAC arm token.  Neither condition
    alone is sufficient for live action.

    Mode resolution (evaluated in order):
      1. If BRDS_LIVE_CONTAINMENT != "1"  -> dry-run (log only)
      2. If -DryRunOverride switch present -> dry-run (caller forces simulation)
      3. If -Armed switch NOT present      -> dry-run
      4. All three conditions met          -> live containment

.PARAMETER Armed
    Must be passed by the caller (trigger_daemon.py) only after it has
    independently verified the HMAC-signed arm token.  This switch alone
    does NOT enable live action — BRDS_LIVE_CONTAINMENT must also be set.

.PARAMETER DryRunOverride
    Force dry-run regardless of other flags.  Used in CI / unit tests.

.EXAMPLE
    # Always dry-run (default lab safe behaviour):
    .\ContainHost.ps1

    # Live containment (VM detonation lab only):
    # Set BRDS_LIVE_CONTAINMENT=1 in environment, then:
    .\ContainHost.ps1 -Armed
#>

[CmdletBinding()]
param (
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

# ── Adapter isolation ─────────────────────────────────────────────────────────
Write-Host "[BRDS-PEC] Executing Host Isolation..."

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

if ($adapters.Count -eq 0) {
    Write-Host "[BRDS-PEC] No active network adapters detected."
    exit 0
}

$disabled = @()
foreach ($adapter in $adapters) {
    Write-Host "[BRDS-PEC] Target adapter: $($adapter.Name) ($($adapter.InterfaceDescription))"
    if ($DryRun) {
        Write-Host "[DRY-RUN] Would disable adapter: $($adapter.Name)"
    } else {
        Write-Host "[CONTAINMENT] Disabling network adapter: $($adapter.Name)..."
        try {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
            Write-Host "[CONTAINMENT] Adapter $($adapter.Name) disabled."
            $disabled += $adapter.Name
        } catch {
            Write-Warning "Could not disable adapter $($adapter.Name): $_"
        }
    }
}

Write-Host "[BRDS-PEC] Host isolation completed. DryRun=$DryRun DisabledAdapters=$($disabled.Count)"
