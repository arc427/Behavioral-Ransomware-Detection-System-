[CmdletBinding()]
param (
    [switch]$DryRun = $false
)

# Force Dry-Run unless environment variable BRDS_DRY_RUN is explicitly set to "0"
if ($env:BRDS_DRY_RUN -ne "0" -and !$DryRun.IsPresent) {
    Write-Host "[SAFETY] BRDS_DRY_RUN environment variable is set. Forcing Dry-Run mode."
    $DryRun = $true
}

# If both are absent, default to dry-run to be safe!
if (-not $env:BRDS_DRY_RUN -and -not $DryRun.IsPresent) {
    Write-Host "[SAFETY] No explicit active mode set. Defaulting to Dry-Run."
    $DryRun = $true
}

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
