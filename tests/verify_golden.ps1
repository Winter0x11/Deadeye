# tests/verify_golden.ps1
# Runs test_target (all modes), captures triage JSON with deadeye, and compares against tests/golden/triage_all.json

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$testTargetExe = Join-Path $repoRoot "build\test_target.exe"
$deadeyeExe = Join-Path $repoRoot "build\deadeye.exe"
$goldenJson = Join-Path $repoRoot "tests\golden\triage_all.json"
$currentJson = Join-Path $repoRoot "tests\triage_current.json"

if (-not (Test-Path $testTargetExe)) {
    Write-Error "test_target.exe not found at $testTargetExe"
    exit 1
}
if (-not (Test-Path $deadeyeExe)) {
    Write-Error "deadeye.exe not found at $deadeyeExe"
    exit 1
}
if (-not (Test-Path $goldenJson)) {
    Write-Error "Golden reference not found at $goldenJson"
    exit 1
}

# 1. Start test_target with auto-pilot paused (all modes pre-allocated)
$proc = Start-Process -FilePath $testTargetExe -ArgumentList "0" -PassThru
Start-Sleep -Milliseconds 600
$targetPid = $proc.Id

try {
    # 2. Run deadeye headless export
    $deadeye = Start-Process -FilePath $deadeyeExe -ArgumentList "--json $targetPid `"$currentJson`"" -PassThru -Wait
    if ($deadeye.ExitCode -ne 0) {
        Write-Error "deadeye --json exited with code $($deadeye.ExitCode)"
        exit 1
    }
} finally {
    Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path $currentJson)) {
    Write-Error "Failed to generate $currentJson"
    exit 1
}

# 3. Compare JSON findings
$golden = Get-Content $goldenJson -Raw | ConvertFrom-Json
$curr = Get-Content $currentJson -Raw | ConvertFrom-Json

# Check rules_not_evaluated
$diffRules = Compare-Object $golden.rules_not_evaluated $curr.rules_not_evaluated
if ($diffRules) {
    Write-Host "[FAIL] rules_not_evaluated mismatch:" -ForegroundColor Red
    $diffRules | Format-Table
    exit 1
}

# Check non-zero severity findings
$goldenFindings = $golden.findings | Where-Object { $_.severity_score -gt 0 } | Sort-Object severity_score -Descending
$currFindings = $curr.findings | Where-Object { $_.severity_score -gt 0 } | Sort-Object severity_score -Descending

if ($goldenFindings.Count -ne $currFindings.Count) {
    Write-Host "[FAIL] Non-zero finding count mismatch: Golden=$($goldenFindings.Count), Current=$($currFindings.Count)" -ForegroundColor Red
    exit 1
}

for ($i = 0; $i -lt $goldenFindings.Count; $i++) {
    $g = $goldenFindings[$i]
    $c = $currFindings[$i]

    if ($g.severity_score -ne $c.severity_score) {
        Write-Host "[FAIL] Finding $i score mismatch: Golden=$($g.severity_score), Current=$($c.severity_score)" -ForegroundColor Red
        exit 1
    }
    if ($g.severity_label -ne $c.severity_label) {
        Write-Host "[FAIL] Finding $i label mismatch: Golden=$($g.severity_label), Current=$($c.severity_label)" -ForegroundColor Red
        exit 1
    }
    $diffFlags = Compare-Object $g.flags $c.flags
    if ($diffFlags) {
        Write-Host "[FAIL] Finding $i flags mismatch:" -ForegroundColor Red
        $diffFlags | Format-Table
        exit 1
    }
}

Write-Host "[OK] Triage verification passed: findings match tests/golden/triage_all.json perfectly!" -ForegroundColor Green
exit 0
