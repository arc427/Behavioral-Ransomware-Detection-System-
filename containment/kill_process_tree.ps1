[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [int]$ParentPid,
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

function Stop-ProcessTree {
    param (
        [int]$targetPid
    )
    
    # Query WMI/CIM for children of this process
    $children = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ParentProcessId -eq $targetPid }
    
    # Recursively kill children first (bottom-up process tree collapse)
    foreach ($child in $children) {
        Stop-ProcessTree -targetPid $child.ProcessId
    }
    
    # Get details of the process
    $procName = "Unknown"
    try {
        $p = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
        if ($p) {
            $procName = $p.Name
        }
    } catch {}
    
    if ($DryRun) {
        Write-Host "[DRY-RUN] Would terminate process: $procName (PID: $targetPid)"
    } else {
        Write-Host "[CONTAINMENT] Terminating process: $procName (PID: $targetPid)..."
        try {
            Stop-Process -Id $targetPid -Force -ErrorAction Stop
            Write-Host "[CONTAINMENT] Process $targetPid ($procName) terminated successfully."
        } catch {
            Write-Warning "Could not terminate process ${targetPid}: $_"
        }
    }
}

Write-Host "[BRDS-PEC] Initiating process tree collapse for PID: $ParentPid..."
Stop-ProcessTree -targetPid $ParentPid
Write-Host "[BRDS-PEC] Process tree collapse completed."
