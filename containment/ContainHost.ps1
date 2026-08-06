[CmdletBinding()]
param (
    [switch]$Armed = $false,
    [switch]$DryRun = $false
)

# Safety lockdown: direct script execution is always a simulation. A future
# reviewed containment service must perform independent token verification.
if ($Armed.IsPresent) { Write-Warning "-Armed is ignored in this project build; containment remains dry-run." }
$DryRun = $true

Write-Host "[BRDS-PEC] Executing Host Isolation..."

# Retrieve active adapter interfaces
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

if ($adapters.Count -eq 0) {
    Write-Host "[BRDS-PEC] No active network adapters detected."
}

foreach ($adapter in $adapters) {
    Write-Host "[BRDS-PEC] Target adapter found: $($adapter.Name) ($($adapter.InterfaceDescription))"
    if ($DryRun) {
        Write-Host "[DRY-RUN] Would disable adapter: $($adapter.Name)"
    } else {
        Write-Host "[CONTAINMENT] Disabling network adapter: $($adapter.Name)..."
        try {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
            Write-Host "[CONTAINMENT] Network adapter $($adapter.Name) disabled successfully."
        } catch {
            Write-Warning "Could not disable adapter $($adapter.Name): $_"
        }
    }
}
Write-Host "[BRDS-PEC] Host isolation completed."
