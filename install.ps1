# install.ps1 - Automated one-line installer for Deadeye (Windows x64)
# Usage:
#   powershell -ep bypass -c "irm https://raw.githubusercontent.com/Winter0x11/Deadeye/main/install.ps1 | iex"

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Deadeye",
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Deadeye - Memory Triage Scanner & Hex Viewer           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$RepoOwner = "Winter0x11"
$RepoName  = "Deadeye"
$ApiUrl    = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"

# 1. Ensure TLS 1.2+ is active
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# 2. Query GitHub for latest release asset or fallback to master branch
Write-Host "[*] Resolving latest Deadeye release..." -ForegroundColor Yellow

$DownloadUrl = $null
try {
    $Release = Invoke-RestMethod -Uri $ApiUrl -UseBasicParsing -TimeoutSec 15
    if ($Release.assets) {
        $ZipAsset = $Release.assets | Where-Object { $_.name -like "*windows-x64*.zip" } | Select-Object -First 1
        if ($ZipAsset) {
            $DownloadUrl = $ZipAsset.browser_download_url
            Write-Host "[+] Found release $($Release.tag_name): $($ZipAsset.name)" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "[!] Could not query GitHub releases API: $_" -ForegroundColor DarkGray
}

if (-not $DownloadUrl) {
    # Direct fallback URL to the compiled zip or pre-packaged tag
    $DownloadUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/v1.0.2/Deadeye-v1.0.2-windows-x64.zip"
    Write-Host "[*] Falling back to standard release asset: $DownloadUrl" -ForegroundColor Yellow
}

# 3. Create install destination directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$TempZip = Join-Path $env:TEMP "Deadeye-Setup.zip"
if (Test-Path $TempZip) {
    Remove-Item $TempZip -Force -ErrorAction SilentlyContinue
}

# 4. Download archive
Write-Host "[*] Downloading Deadeye binary..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
} catch {
    Write-Host "[X] Download failed from $($DownloadUrl): $_" -ForegroundColor Red
    return
}

# 5. Extract files
Write-Host "[*] Extracting binaries to $InstallDir..." -ForegroundColor Yellow
Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
Remove-Item $TempZip -Force -ErrorAction SilentlyContinue

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
