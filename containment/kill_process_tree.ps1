[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [int]$ParentPid,
    [switch]$Armed = $false,
    [switch]$DryRun = $false
)

# Safety lockdown: direct script execution is always a simulation. A future
# reviewed containment service must perform independent token verification.
if ($Armed.IsPresent) { Write-Warning "-Armed is ignored in this project build; containment remains dry-run." }
$DryRun = $true

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
    
    # Protected critical Windows system processes
    $PROTECTED_PROCESSES = @('lsass', 'csrss', 'smss', 'wininit', 'winlogon', 'services', 'system', 'svchost', 'explorer', 'spoolsv', 'dwm')

    # Get details of the process
    $procName = "Unknown"
    try {
        $p = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
        if ($p) {
            $procName = $p.Name
        }
    } catch {}

    if ($PROTECTED_PROCESSES -contains $procName.ToLower()) {
        Write-Host "[SAFETY] Refusing to terminate protected system process: $procName (PID: $targetPid)"
        return
    }
    
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
