<#
.SYNOPSIS
    Builds the Deadeye Defensive Memory Triage Scanner and Test Targets.
.DESCRIPTION
    Supports MinGW GCC and Microsoft Visual C++ (MSVC) toolchains with zero warnings.
    Compiles all modular source files under src/**/*.cpp and embeds resources.
.PARAMETER Toolchain
    Toolchain to build with: 'all', 'mingw', or 'msvc'. Default is 'all'.
.PARAMETER Config
    Build configuration: 'Release' or 'Debug'. Default is 'Release'.
.PARAMETER BuildTests
    Whether to build test targets (tests/test_target.cpp). Default is $true.
#>

[CmdletBinding()]
param(
    [ValidateSet('all', 'mingw', 'msvc')]
    [string]$Toolchain = 'all',

    [ValidateSet('Release', 'Debug')]
    [string]$Config = 'Release',

    [switch]$BuildTests = $true
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

$buildDir = Join-Path $repoRoot "build"
if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

# Collect all source files
$srcFiles = Get-ChildItem -Path (Join-Path $repoRoot "src") -Filter *.cpp -Recurse | Select-Object -ExpandProperty FullName
$resourceRc = Join-Path $repoRoot "src\resources\deadeye.rc"
$resourceDir = Join-Path $repoRoot "src\resources"
$testTargetSrc = Join-Path $repoRoot "tests\test_target.cpp"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Deadeye Modular Build System                           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Configuration : $Config" -ForegroundColor DarkGray
Write-Host "Source Files  : $($srcFiles.Count) C++ translation units" -ForegroundColor DarkGray

# -------------------------------------------------------------------------
# Toolchain: MinGW GCC
# -------------------------------------------------------------------------
function Build-MinGW {
    Write-Host "`n[*] Building with MinGW-w64 GCC..." -ForegroundColor Yellow

    if (-not (Get-Command g++ -ErrorAction SilentlyContinue) -or -not (Get-Command windres -ErrorAction SilentlyContinue)) {
        $candidatePaths = @(
            "C:\msys64\mingw64\bin",
            "$env:RUNNER_TEMP\msys64\mingw64\bin",
            "D:\a\_temp\msys64\mingw64\bin",
            "C:\mingw64\bin"
        )
        foreach ($cp in $candidatePaths) {
            if ($cp -and (Test-Path "$cp\g++.exe") -and (Test-Path "$cp\windres.exe")) {
                Write-Host "  -> Found MinGW in $cp, adding to PATH..." -ForegroundColor DarkGray
                $env:PATH = "$cp;$env:PATH"
                break
            }
        }
    }

    $gccCmd = Get-Command g++ -ErrorAction SilentlyContinue
    $windresCmd = Get-Command windres -ErrorAction SilentlyContinue

    if (-not $gccCmd -or -not $windresCmd) {
        Write-Warning "MinGW GCC or windres not found in PATH. Skipping MinGW build."
        return $false
    }

    $resObj = Join-Path $buildDir "deadeye_res.o"
    $exeOut = Join-Path $buildDir "deadeye.exe"

    Write-Host "  -> Compiling resources ($resourceRc)..." -ForegroundColor DarkGray
    & windres -I $resourceDir -i $resourceRc -O coff -o $resObj
    if ($LASTEXITCODE -ne 0) {
        throw "windres failed with exit code $LASTEXITCODE"
    }

    $optFlag = if ($Config -eq 'Release') { "-O2" } else { "-g" }
    $gccArgs = @(
        "-std=c++17", "-m64",
        "-Wall", "-Wextra", "-pedantic",
        $optFlag,
        "-static", "-static-libgcc", "-static-libstdc++",
        "-Isrc"
    ) + $srcFiles + @(
        $resObj,
        "-o", $exeOut,
        "-mwindows",
        "-ladvapi32", "-lcomctl32", "-lcomdlg32", "-lgdi32", "-luser32"
    )

    Write-Host "  -> Compiling deadeye.exe..." -ForegroundColor DarkGray
    & g++ @gccArgs
    if ($LASTEXITCODE -ne 0) {
        throw "MinGW compilation failed with exit code $LASTEXITCODE"
    }

    Write-Host "  [+] MinGW build successful: $exeOut" -ForegroundColor Green

    if ($BuildTests -and (Test-Path $testTargetSrc)) {
        $testExe = Join-Path $buildDir "test_target.exe"
        Write-Host "  -> Compiling test target ($testExe)..." -ForegroundColor DarkGray
        & g++ -std=c++17 -m64 -Wall -Wextra -pedantic $optFlag $testTargetSrc -o $testExe
        if ($LASTEXITCODE -ne 0) {
            throw "MinGW test_target compilation failed with exit code $LASTEXITCODE"
        }
        Write-Host "  [+] MinGW test target: $testExe" -ForegroundColor Green
    }

    return $true
}

# -------------------------------------------------------------------------
# Toolchain: MSVC
# -------------------------------------------------------------------------
function Build-MSVC {
    Write-Host "`n[*] Building with Microsoft Visual C++ (MSVC)..." -ForegroundColor Yellow

    # Locate vcvars64.bat if cl.exe not currently loaded in environment
    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        $vcVarsPath = $null
        if (Test-Path $vswhere) {
            $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
            if ($vsPath -and (Test-Path "$vsPath\VC\Auxiliary\Build\vcvars64.bat")) {
                $vcVarsPath = "$vsPath\VC\Auxiliary\Build\vcvars64.bat"
            }
        }
        if (-not $vcVarsPath) {
            $commonPaths = @(
                "$env:ProgramFiles\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
                "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
                "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
            )
            foreach ($p in $commonPaths) {
                if (Test-Path $p) {
                    $vcVarsPath = $p
                    break
                }
            }
        }

        if ($vcVarsPath) {
            Write-Host "  -> Initializing MSVC environment via $vcVarsPath..." -ForegroundColor DarkGray
            $cmdOutput = cmd.exe /c "`"$vcVarsPath`" >nul 2>&1 && set"
            foreach ($line in $cmdOutput) {
                if ($line -match "^([^=]+)=(.*)$") {
                    [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
                }
            }
        }
    }

    $clCmd = Get-Command cl.exe -ErrorAction SilentlyContinue
    $rcCmd = Get-Command rc.exe -ErrorAction SilentlyContinue

    if (-not $clCmd -or -not $rcCmd) {
        Write-Warning "MSVC cl.exe or rc.exe not found. Skipping MSVC build."
        return $false
    }

    $resFile = Join-Path $buildDir "deadeye_msvc_res.res"
    $exeOut = Join-Path $buildDir "deadeye_msvc.exe"

    Write-Host "  -> Compiling resources ($resourceRc)..." -ForegroundColor DarkGray
    & rc /nologo /i $resourceDir /fo $resFile $resourceRc
    if ($LASTEXITCODE -ne 0) {
        throw "rc.exe failed with exit code $LASTEXITCODE"
    }

    $optFlag = if ($Config -eq 'Release') { "/O2" } else { "/Od /Zi" }
    $clArgs = @(
        "/std:c++17", "/EHsc", "/W4", $optFlag,
        "/Isrc", "/D_CRT_SECURE_NO_WARNINGS", "/DNOMINMAX", "/utf-8"
    ) + $srcFiles + @(
        $resFile,
        "/Fe:$exeOut",
        "/link", "/SUBSYSTEM:WINDOWS",
        "advapi32.lib", "comctl32.lib", "comdlg32.lib", "user32.lib", "gdi32.lib"
    )

    Write-Host "  -> Compiling deadeye_msvc.exe..." -ForegroundColor DarkGray
    & cl @clArgs
    if ($LASTEXITCODE -ne 0) {
        throw "MSVC compilation failed with exit code $LASTEXITCODE"
    }

    # Clean up intermediate .obj files
    Get-ChildItem -Path $repoRoot -Filter *.obj | Remove-Item -Force -ErrorAction SilentlyContinue

    Write-Host "  [+] MSVC build successful: $exeOut" -ForegroundColor Green

    if ($BuildTests -and (Test-Path $testTargetSrc)) {
        $testExe = Join-Path $buildDir "test_target_msvc.exe"
        Write-Host "  -> Compiling MSVC test target ($testExe)..." -ForegroundColor DarkGray
        & cl /std:c++17 /EHsc /W4 $optFlag /D_CRT_SECURE_NO_WARNINGS $testTargetSrc "/Fe:$testExe"
        Get-ChildItem -Path $repoRoot -Filter test_target.obj | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] MSVC test target: $testExe" -ForegroundColor Green
    }

    return $true
}

# -------------------------------------------------------------------------
# Execution
# -------------------------------------------------------------------------
$builtAny = $false

if ($Toolchain -eq 'all' -or $Toolchain -eq 'mingw') {
    $builtAny = (Build-MinGW) -or $builtAny
}

if ($Toolchain -eq 'all' -or $Toolchain -eq 'msvc') {
    $builtAny = (Build-MSVC) -or $builtAny
}

if (-not $builtAny) {
    Write-Error "No toolchains succeeded in building Deadeye."
    exit 1
}

Write-Host "`n[SUCCESS] Build finished successfully!`n" -ForegroundColor Green
