<#
    PyShare end-to-end demo (Windows PowerShell).

    Runs `pyshare scan` against the three bundled sample projects and
    prints a pass/fail report.

    Prerequisites:
      - Docker Desktop running with pyshare-neo4j container started
        (see DEMO.md for the docker run command)
      - .env populated with NEO4J_PASSWORD + JARVIS_CLI_PATH
      - pyshare installed:  pip install -e .

    Run from the repo root:
      pwsh ./scripts/run_demo.ps1
#>

# Native tools (python, docker, pip) write deprecation / progress text
# to stderr that PowerShell would otherwise treat as a script error
# under ``$ErrorActionPreference = "Stop"``. We rely on exit codes
# instead.
$ErrorActionPreference = "Continue"
$env:PYTHONIOENCODING = "utf-8"
$env:OPENBLAS_NUM_THREADS = "1"

$repoRoot = Split-Path -Parent $PSScriptRoot
$samplesRoot = Join-Path $repoRoot "sample_projects"
$cveCacheSrc = Join-Path $samplesRoot "cve_cache"
$userCacheDir = Join-Path $HOME ".pyshare\cve"

function Write-Header($msg) {
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor Cyan
    Write-Host $msg -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor Cyan
}

function Test-Tool($name, $cmd) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Host "  [MISSING] $name ('$cmd' not in PATH)" -ForegroundColor Red
        return $false
    }
    Write-Host "  [OK]      $name"
    return $true
}

# ---------------------------------------------------------------------
# 1. Prerequisite checks
# ---------------------------------------------------------------------
Write-Header "1. Prerequisite checks"
$allOk = $true
$allOk = (Test-Tool "Python"  "python") -and $allOk
$allOk = (Test-Tool "pip"     "pip")    -and $allOk
$allOk = (Test-Tool "Docker"  "docker") -and $allOk

# pyshare CLI
$pyshareOk = $false
try {
    & python -m pyshare.cli.main --help *> $null
    if ($LASTEXITCODE -eq 0) { $pyshareOk = $true }
} catch {}
if ($pyshareOk) { Write-Host "  [OK]      pyshare CLI importable" }
else {
    Write-Host "  [MISSING] pyshare CLI -- run 'pip install -e .' first" -ForegroundColor Red
    $allOk = $false
}

# Neo4j container
$neo4jUp = $false
try {
    $containers = docker ps --filter "name=pyshare-neo4j" --format "{{.Status}}" 2>$null
    if ($containers -and $containers.StartsWith("Up")) { $neo4jUp = $true }
} catch {}
if ($neo4jUp) { Write-Host "  [OK]      pyshare-neo4j container is Up" }
else {
    Write-Host "  [MISSING] Neo4j container not running. Start it with:" -ForegroundColor Red
    Write-Host "      docker run -d --name pyshare-neo4j ``" -ForegroundColor Yellow
    Write-Host "          -p 7474:7474 -p 7687:7687 ``" -ForegroundColor Yellow
    Write-Host "          -e NEO4J_AUTH=neo4j/pyshare-dev-pwd neo4j:5-community" -ForegroundColor Yellow
    $allOk = $false
}

if (-not $allOk) {
    Write-Host "`nPrerequisites missing -- see DEMO.md for full setup." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------
# 2. Seed CVE cache
# ---------------------------------------------------------------------
Write-Header "2. Seeding CVE cache (~/.pyshare/cve/)"
if (-not (Test-Path $userCacheDir)) {
    New-Item -ItemType Directory -Path $userCacheDir -Force | Out-Null
}
Get-ChildItem $cveCacheSrc -Filter "*.json" | ForEach-Object {
    $dst = Join-Path $userCacheDir $_.Name
    Copy-Item $_.FullName $dst -Force
    Write-Host "  copied $($_.Name) -> $dst"
}

# ---------------------------------------------------------------------
# 3. Setup .venv per sample + install requirements
# ---------------------------------------------------------------------
$cases = @(
    @{
        Name   = "affected_yaml";
        Cve    = "CVE-2020-14343";
        Vf     = "yaml.load";
        Expect = "AFFECTED";
    },
    @{
        Name   = "safe_yaml";
        Cve    = "CVE-2020-14343";
        Vf     = "yaml.load";
        Expect = "NOT_AFFECTED";
    },
    @{
        Name   = "affected_requests";
        Cve    = "CVE-2024-35195";
        Vf     = "requests.sessions.Session.request";
        Expect = "AFFECTED";
    }
)

Write-Header "3. Provisioning sample-project venvs"
foreach ($c in $cases) {
    $proj = Join-Path $samplesRoot $c.Name
    $venvPy = Join-Path $proj ".venv\Scripts\python.exe"
    if (Test-Path $venvPy) {
        Write-Host "  [skip]   $($c.Name): venv exists"
        continue
    }
    Write-Host "  [setup]  $($c.Name): creating venv + installing requirements..." -ForegroundColor Yellow
    & python -m venv (Join-Path $proj ".venv")
    # Pip writes deprecation notices to stderr; suppress its output but
    # still trust the exit code.
    $pipOut = & $venvPy -m pip install --quiet --disable-pip-version-check `
        -r (Join-Path $proj "requirements.txt") 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [FAIL]   pip install failed for $($c.Name)" -ForegroundColor Red
        Write-Host ($pipOut | Out-String) -ForegroundColor DarkGray
    } else {
        Write-Host "  [ok]     $($c.Name): venv ready"
    }
}

# ---------------------------------------------------------------------
# 4. Run pyshare scan on each sample
# ---------------------------------------------------------------------
Write-Header "4. Running pyshare scan on samples"
$results = @()
foreach ($c in $cases) {
    $proj = Join-Path $samplesRoot $c.Name
    Write-Host ""
    Write-Host "[CASE] $($c.Name)" -ForegroundColor Magenta
    Write-Host "  CVE      : $($c.Cve)"
    Write-Host "  vf       : $($c.Vf)"
    Write-Host "  Expected : $($c.Expect)"

    $jsonOut = & python -m pyshare.cli.main scan `
        --cve $c.Cve `
        --project $proj `
        --vf $c.Vf `
        --format json 2>$null

    try {
        $obj = $jsonOut | ConvertFrom-Json
        $verdict = $obj.verdict
    } catch {
        $verdict = "PARSE_ERROR"
    }

    $pass = ($verdict -eq $c.Expect)
    $tag = if ($pass) { "PASS" } else { "FAIL" }
    $color = if ($pass) { "Green" } else { "Red" }
    Write-Host "  Actual   : $verdict   [$tag]" -ForegroundColor $color

    $results += [pscustomobject]@{
        Sample   = $c.Name
        Expected = $c.Expect
        Actual   = $verdict
        Pass     = $pass
    }
}

# ---------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------
Write-Header "5. Summary"
$results | Format-Table -AutoSize
$passed = ($results | Where-Object { $_.Pass }).Count
$total = $results.Count
$color = if ($passed -eq $total) { "Green" } else { "Red" }
Write-Host "`n$passed / $total samples produced the expected verdict." -ForegroundColor $color

if ($passed -ne $total) { exit 1 }
