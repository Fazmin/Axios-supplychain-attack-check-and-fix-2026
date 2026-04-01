# ============================================================================
# Axios Supply Chain Attack — Detection & Fix Script (Windows)
# ============================================================================
#
# Usage:
#   .\check_and_fix.ps1                        # Scan and fix the current directory
#   .\check_and_fix.ps1 -Path D:\Projects      # Scan and fix every project under a folder
#   .\check_and_fix.ps1 -Path C:\              # Scan and fix the whole drive
#   .\check_and_fix.ps1 -Path D:\Projects -MaxDepth 2   # Limit folder depth
#   .\check_and_fix.ps1 -CheckOnly             # Only scan, do not modify anything
#   .\check_and_fix.ps1 -SafeVersion "1.13.7"  # Pin to a specific safe version
#   .\check_and_fix.ps1 -SkipSystemChecks      # Only run per-project checks
#
# ============================================================================

param(
    [string]$Path,
    [int]$MaxDepth = 10,
    [switch]$SkipSystemChecks,
    [switch]$CheckOnly,
    [string]$SafeVersion
)

# ── Helpers ─────────────────────────────────────────────────────────────────

function Resolve-SafeAxiosVersion {
    param([string]$Preferred)

    if ($Preferred) { return $Preferred }

    try {
        $latest = (npm view axios version 2>$null)
        if ($latest) {
            $latest = $latest.Trim()
            if ($latest -and $latest -notmatch '^(1\.14\.1|0\.30\.4)$') {
                return $latest
            }
        }
    } catch {}

    return "1.14.0"
}

function Repair-AxiosProject {
    param(
        [string]$ProjectDir,
        [string]$Version
    )

    $fixed = $false

    # Pin axios version in package.json
    $pkgJsonPath = Join-Path $ProjectDir "package.json"
    if (Test-Path $pkgJsonPath) {
        $content = Get-Content $pkgJsonPath -Raw
        $pattern = '("axios"\s*:\s*")[^"]*(")'
        $newContent = $content -replace $pattern, "`${1}$Version`${2}"
        if ($newContent -ne $content) {
            Set-Content -Path $pkgJsonPath -Value $newContent -NoNewline
            Write-Host "    [fix]       package.json: axios pinned to $Version" -ForegroundColor Cyan
            $fixed = $true
        }
    }

    # Remove compromised installed packages
    $axiosDir = Join-Path $ProjectDir "node_modules\axios"
    if (Test-Path $axiosDir) {
        Remove-Item -Path $axiosDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "    [fix]       Removed node_modules\axios" -ForegroundColor Cyan
        $fixed = $true
    }

    $malDir = Join-Path $ProjectDir "node_modules\plain-crypto-js"
    if (Test-Path $malDir) {
        Remove-Item -Path $malDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "    [fix]       Removed node_modules\plain-crypto-js" -ForegroundColor Cyan
        $fixed = $true
    }

    # Remove lockfiles that contain compromised resolutions
    $lockPath = Join-Path $ProjectDir "package-lock.json"
    if (Test-Path $lockPath) {
        $lockContent = Get-Content $lockPath -Raw -ErrorAction SilentlyContinue
        if ($lockContent -match '1\.14\.1|0\.30\.4|plain-crypto-js') {
            Remove-Item -Path $lockPath -Force -ErrorAction SilentlyContinue
            Write-Host "    [fix]       Removed compromised package-lock.json" -ForegroundColor Cyan
            $fixed = $true
        }
    }

    $yarnLock = Join-Path $ProjectDir "yarn.lock"
    if (Test-Path $yarnLock) {
        $yarnContent = Get-Content $yarnLock -Raw -ErrorAction SilentlyContinue
        if ($yarnContent -match '1\.14\.1|0\.30\.4|plain-crypto-js') {
            Remove-Item -Path $yarnLock -Force -ErrorAction SilentlyContinue
            Write-Host "    [fix]       Removed compromised yarn.lock" -ForegroundColor Cyan
            $fixed = $true
        }
    }

    if ($fixed) {
        Write-Host "    [fix]       >> Run 'npm install' to regenerate clean dependencies" -ForegroundColor Yellow
    }

    return $fixed
}

function Test-ProjectForAxiosAttack {
    param(
        [string]$ProjectDir,
        [bool]$Fix = $false,
        [string]$FixVersion = "1.14.0"
    )

    $projectFound = $false

    Write-Host ""
    Write-Host "  ── $ProjectDir" -ForegroundColor White
    Write-Host ""

    # Check 1: package.json — does it even use axios?
    $pkgJsonPath = Join-Path $ProjectDir "package.json"
    if (Test-Path $pkgJsonPath) {
        $pkgContent = Get-Content $pkgJsonPath -Raw -ErrorAction SilentlyContinue
        if ($pkgContent -notmatch '"axios"') {
            Write-Host "    [axios]     SKIP: Project does not depend on axios" -ForegroundColor DarkGray
            return @{ Found = $false; Fixed = $false }
        }
    }

    # Check 2: Installed axios version via node_modules (fast, no npm call)
    $axiosPkgJson = Join-Path $ProjectDir "node_modules\axios\package.json"
    if (Test-Path $axiosPkgJson) {
        $axiosMeta = Get-Content $axiosPkgJson -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($axiosMeta.version -match '^(1\.14\.1|0\.30\.4)') {
            Write-Host "    [version]   !! AFFECTED: axios $($axiosMeta.version) installed" -ForegroundColor Red
            $projectFound = $true
        } else {
            Write-Host "    [version]   OK: axios $($axiosMeta.version)" -ForegroundColor Green
        }
    } else {
        Write-Host "    [version]   SKIP: node_modules not present (run npm install first)" -ForegroundColor DarkGray
    }

    # Check 3: Lockfile
    $lockPath = Join-Path $ProjectDir "package-lock.json"
    if (Test-Path $lockPath) {
        $lockHit = Select-String -Path $lockPath -Pattern "1\.14\.1|0\.30\.4|plain-crypto-js" -Quiet
        if ($lockHit) {
            Write-Host "    [lockfile]  !! AFFECTED: Compromised reference in lockfile" -ForegroundColor Red
            $projectFound = $true
        } else {
            Write-Host "    [lockfile]  OK: Lockfile clean" -ForegroundColor Green
        }
    } else {
        $yarnLock = Join-Path $ProjectDir "yarn.lock"
        if (Test-Path $yarnLock) {
            $yarnHit = Select-String -Path $yarnLock -Pattern "1\.14\.1|0\.30\.4|plain-crypto-js" -Quiet
            if ($yarnHit) {
                Write-Host "    [lockfile]  !! AFFECTED: Compromised reference in yarn.lock" -ForegroundColor Red
                $projectFound = $true
            } else {
                Write-Host "    [lockfile]  OK: yarn.lock clean" -ForegroundColor Green
            }
        } else {
            Write-Host "    [lockfile]  SKIP: No lockfile found" -ForegroundColor DarkGray
        }
    }

    # Check 4: Malicious dependency on disk
    $malPkg = Join-Path $ProjectDir "node_modules\plain-crypto-js"
    if (Test-Path $malPkg) {
        Write-Host "    [malware]   !! AFFECTED: plain-crypto-js EXISTS in node_modules" -ForegroundColor Red
        $projectFound = $true
    } else {
        Write-Host "    [malware]   OK: plain-crypto-js not found" -ForegroundColor Green
    }

    # Auto-fix if compromise detected
    $wasFixed = $false
    if ($projectFound -and $Fix) {
        Write-Host ""
        Write-Host "    [fix]       Applying automatic fixes..." -ForegroundColor Cyan
        $wasFixed = Repair-AxiosProject -ProjectDir $ProjectDir -Version $FixVersion
    }

    if ($projectFound) {
        if ($wasFixed) {
            Write-Host "    [result]    !! COMPROMISED — fixes applied" -ForegroundColor Yellow
        } else {
            Write-Host "    [result]    !! COMPROMISED" -ForegroundColor Red
        }
    } else {
        Write-Host "    [result]    CLEAN" -ForegroundColor Green
    }

    return @{ Found = $projectFound; Fixed = $wasFixed }
}

# ── Banner ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Axios Supply Chain Attack - Check `& Fix" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ── Resolve safe version ───────────────────────────────────────────────────

$doFix = -not $CheckOnly
$resolvedVersion = "1.14.0"

if ($doFix) {
    Write-Host "  Resolving safe axios version..." -ForegroundColor DarkGray
    $resolvedVersion = Resolve-SafeAxiosVersion -Preferred $SafeVersion
    Write-Host "  Safe version: $resolvedVersion" -ForegroundColor Green
} else {
    Write-Host "  Mode: Check only (no fixes will be applied)" -ForegroundColor DarkGray
}

# ── Discover projects ───────────────────────────────────────────────────────

$scanRoot = if ($Path) { (Resolve-Path $Path -ErrorAction Stop).Path } else { $PWD.Path }
$isSingleProject = -not $Path

if ($isSingleProject) {
    Write-Host "  Scope: Single project ($scanRoot)" -ForegroundColor DarkGray
} else {
    Write-Host "  Scope: Recursive scan (depth $MaxDepth)" -ForegroundColor DarkGray
    Write-Host "  Root:  $scanRoot" -ForegroundColor DarkGray
}

$globalFound = $false
$affectedProjects = [System.Collections.Generic.List[string]]::new()
$fixedProjects    = [System.Collections.Generic.List[string]]::new()
$scannedCount = 0

if ($isSingleProject) {
    $scannedCount = 1
    $result = Test-ProjectForAxiosAttack -ProjectDir $scanRoot -Fix $doFix -FixVersion $resolvedVersion
    if ($result.Found) {
        $globalFound = $true
        $affectedProjects.Add($scanRoot)
        if ($result.Fixed) { $fixedProjects.Add($scanRoot) }
    }
} else {
    Write-Host ""
    Write-Host "  Discovering Node.js projects..." -ForegroundColor Yellow

    $projects = Get-ChildItem -Path $scanRoot -Filter "package.json" -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -notmatch '[\\/]node_modules[\\/]' -and
            $_.FullName -notmatch '[\\/]\.cache[\\/]' -and
            $_.FullName -notmatch '[\\/]\.next[\\/]'
        } |
        ForEach-Object { $_.Directory.FullName }

    $total = @($projects).Count
    if ($total -eq 0) {
        Write-Host "  No Node.js projects found under $scanRoot" -ForegroundColor DarkGray
    } else {
        Write-Host "  Found $total project(s)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  PROJECT SCAN" -ForegroundColor Yellow
        Write-Host "────────────────────────────────────────────" -ForegroundColor DarkGray

        foreach ($proj in $projects) {
            $scannedCount++
            $result = Test-ProjectForAxiosAttack -ProjectDir $proj -Fix $doFix -FixVersion $resolvedVersion
            if ($result.Found) {
                $globalFound = $true
                $affectedProjects.Add($proj)
                if ($result.Fixed) { $fixedProjects.Add($proj) }
            }
        }
    }
}

# ── System-wide checks (run once) ──────────────────────────────────────────

if (-not $SkipSystemChecks) {
    Write-Host ""
    Write-Host "────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  SYSTEM CHECKS" -ForegroundColor Yellow
    Write-Host "────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    # RAT artifacts
    Write-Host "  [RAT] Checking for wt.exe and temp payloads..." -ForegroundColor Yellow
    $wtPath = "$env:PROGRAMDATA\wt.exe"
    if (Test-Path $wtPath) {
        Write-Host "    !! CRITICAL: Windows RAT found at $wtPath" -ForegroundColor Red
        Get-Item $wtPath | Format-List Name, Length, LastWriteTime
        $globalFound = $true
    } else {
        Write-Host "    OK: wt.exe not found in ProgramData" -ForegroundColor Green
    }

    $vbsPath = "$env:TEMP\6202033.vbs"
    $ps1Path = "$env:TEMP\6202033.ps1"
    if ((Test-Path $vbsPath) -or (Test-Path $ps1Path)) {
        Write-Host "    !! WARNING: Temp payload files found" -ForegroundColor Red
        $globalFound = $true
    } else {
        Write-Host "    OK: No temp payload files" -ForegroundColor Green
    }

    # C2 connections
    Write-Host ""
    Write-Host "  [C2] Checking for active C2 connections..." -ForegroundColor Yellow
    $c2Check = netstat -an 2>$null | Select-String "142.11.206.73"
    if ($c2Check) {
        Write-Host "    !! CRITICAL: Active connection to C2 (142.11.206.73)" -ForegroundColor Red
        Write-Host "    $c2Check"
        $globalFound = $true
    } else {
        Write-Host "    OK: No active C2 connections" -ForegroundColor Green
    }
}

# ── Summary ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan

if (-not $isSingleProject) {
    Write-Host "  Projects scanned:  $scannedCount" -ForegroundColor White
    Write-Host "  Projects affected: $($affectedProjects.Count)" -ForegroundColor $(if ($affectedProjects.Count -gt 0) { "Red" } else { "Green" })
    if ($doFix -and $fixedProjects.Count -gt 0) {
        Write-Host "  Projects fixed:    $($fixedProjects.Count)" -ForegroundColor Cyan
    }
    if ($affectedProjects.Count -gt 0) {
        Write-Host ""
        Write-Host "  Affected:" -ForegroundColor Red
        foreach ($ap in $affectedProjects) {
            $tag = if ($fixedProjects -contains $ap) { " (fixed)" } else { "" }
            Write-Host "    - $ap$tag" -ForegroundColor $(if ($tag) { "Yellow" } else { "Red" })
        }
    }
    Write-Host ""
}

if ($globalFound) {
    if ($doFix -and $fixedProjects.Count -gt 0) {
        Write-Host "  FIXES APPLIED" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Next steps:" -ForegroundColor Yellow
        Write-Host "  1. Run 'npm install' in each fixed project to regenerate lockfile"
        Write-Host "  2. Rotate ALL credentials (npm tokens, cloud keys, deploy keys, etc.)"
        Write-Host "  3. Block sfrclak.com and 142.11.206.73"
        Write-Host "  4. If RAT found: FULL SYSTEM REBUILD"
    } else {
        Write-Host "  !! POTENTIAL COMPROMISE DETECTED" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Remediation:" -ForegroundColor Yellow
        Write-Host "  1. Re-run with auto-fix: .\check_and_fix.ps1 -Path <folder>"
        Write-Host "     Or manually: npm install axios@1.14.0 --save-exact"
        Write-Host "  2. Remove node_modules and reinstall: rm -r node_modules; npm ci"
        Write-Host "  3. Rotate ALL credentials"
        Write-Host "  4. Block sfrclak.com and 142.11.206.73"
        Write-Host "  5. If RAT found: FULL SYSTEM REBUILD"
    }
} else {
    Write-Host "  ALL CLEAR" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Preventive: npm install axios@1.14.0 --save-exact"
    Write-Host "  Set: npm config set min-release-age 3"
}
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
