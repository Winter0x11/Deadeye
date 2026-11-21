# install.ps1 - Automated one-line installer for Deadeye (Windows x64)
# Usage:
#   powershell -ep bypass -c "irm https://raw.githubusercontent.com/Winter0x11/Deadeye/main/install.ps1 | iex"

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Deadeye",
    [string]$SourceExe = "",
    [string]$Version = "",
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Deadeye - Memory Triage Scanner & Hex Viewer           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Stop running Deadeye instance for clean update
Get-Process -Name "deadeye" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "[*] Stopping running Deadeye instance (PID $($_.Id)) for update..." -ForegroundColor Yellow
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$ExePath = Join-Path $InstallDir "deadeye.exe"

# 2. Check for current local build first (workspace, extracted archive, or specified path)
$LocalCandidate = if ($SourceExe -and (Test-Path $SourceExe)) {
    $SourceExe
} else {
    $candidates = @(
        (Join-Path (Get-Location) "deadeye.exe"),
        (Join-Path (Get-Location) "build\bin\deadeye.exe"),
        (Join-Path (Get-Location) "build\bin\Release\deadeye.exe"),
        (Join-Path (Get-Location) "build\Release\deadeye.exe"),
        (Join-Path (Get-Location) "build\deadeye.exe")
    )
    if ($PSScriptRoot) {
        $candidates += (Join-Path $PSScriptRoot "deadeye.exe")
        $candidates += (Join-Path $PSScriptRoot "build\bin\deadeye.exe")
        $candidates += (Join-Path $PSScriptRoot "build\bin\Release\deadeye.exe")
        $candidates += (Join-Path $PSScriptRoot "build\Release\deadeye.exe")
        $candidates += (Join-Path $PSScriptRoot "build\deadeye.exe")
    }
    $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}

if ($LocalCandidate) {
    Write-Host "[+] Installing from current local build: $LocalCandidate" -ForegroundColor Green
    Copy-Item -Path $LocalCandidate -Destination $ExePath -Force
} else {
    $RepoOwner = "Winter0x11"
    $RepoName  = "Deadeye"
    $ApiUrl    = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"

    # Ensure TLS 1.2+ is active
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $DownloadUrl = $null

    if ($Version) {
        $tagToUse = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
        $DownloadUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/$tagToUse/Deadeye-$tagToUse-windows-x64.zip"
        Write-Host "[*] Targeting specified release version: $tagToUse" -ForegroundColor Yellow
    } else {
        # Query GitHub for latest release asset
        Write-Host "[*] Resolving latest Deadeye release..." -ForegroundColor Yellow

        try {
            $Releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$RepoOwner/$RepoName/releases" -UseBasicParsing -TimeoutSec 15
            foreach ($rel in $Releases) {
                if ($rel.assets) {
                    $ZipAsset = $rel.assets | Where-Object { $_.name -like "*windows-x64*.zip" } | Select-Object -First 1
                    if ($ZipAsset) {
                        $DownloadUrl = $ZipAsset.browser_download_url
                        Write-Host "[+] Found release $($rel.tag_name): $($ZipAsset.name)" -ForegroundColor Green
                        break
                    }
                }
            }
        } catch {
            Write-Host "[!] Could not query GitHub releases API: $_" -ForegroundColor DarkGray
        }

        if (-not $DownloadUrl) {
            # Fallback to /releases/latest redirect header (rate-limit safe)
            try {
                $Req = [System.Net.HttpWebRequest]::Create("https://github.com/$RepoOwner/$RepoName/releases/latest")
                $Req.AllowAutoRedirect = $false
                $Resp = $Req.GetResponse()
                $Location = $Resp.GetResponseHeader("Location")
                $Resp.Close()
                if ($Location -match "/tag/(v[0-9\.]+)") {
                    $LatestTag = $Matches[1]
                    $DownloadUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/$LatestTag/Deadeye-$LatestTag-windows-x64.zip"
                    Write-Host "[+] Resolved latest release via redirect: $LatestTag" -ForegroundColor Green
                }
            } catch {
                throw "Could not resolve the latest Deadeye release. Check your internet connection and try again."
            }
        }
    }

    $TempZip = Join-Path $env:TEMP "Deadeye-Setup.zip"
    if (Test-Path $TempZip) {
        Remove-Item $TempZip -Force -ErrorAction SilentlyContinue
    }

    # Download archive
    Write-Host "[*] Downloading Deadeye binary..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
    } catch {
        Write-Host "[X] Download failed from $($DownloadUrl): $_" -ForegroundColor Red
        return
    }

    # Extract files
    Write-Host "[*] Extracting binaries to $InstallDir..." -ForegroundColor Yellow
    Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
    Remove-Item $TempZip -Force -ErrorAction SilentlyContinue
}

$ExePath = Join-Path $InstallDir "deadeye.exe"
if (-not (Test-Path $ExePath)) {
    Write-Host "[X] Installation failed: deadeye.exe not found in $InstallDir" -ForegroundColor Red
    return
}

# 6. Add to user PATH if not already present
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "[*] Adding $InstallDir to user PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
}

# 7. Create Start Menu shortcut
try {
    $WshShell = New-Object -ComObject WScript.Shell
    $StartMenuPath = [Environment]::GetFolderPath("StartMenu")
    $ShortcutPath = Join-Path $StartMenuPath "Programs\Deadeye.lnk"
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $ExePath
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.IconLocation = "$ExePath,0"
    $Shortcut.Description = "Deadeye Windows Process Memory Triage Scanner & Hex Viewer"
    $Shortcut.Save()
    Write-Host "[+] Start Menu shortcut created: Deadeye" -ForegroundColor Green
} catch {
    # Non-fatal if shortcut creation fails
}

Write-Host ""
Write-Host "[SUCCESS] Deadeye installed successfully!" -ForegroundColor Green
Write-Host "Location: $ExePath" -ForegroundColor Cyan
Write-Host "You can now run 'deadeye' from any PowerShell or Command Prompt." -ForegroundColor Cyan
Write-Host ""

# 8. Launch Deadeye
if (-not $NoLaunch) {
    Write-Host "[*] Launching Deadeye..." -ForegroundColor Yellow
    Start-Process -FilePath $ExePath
}
