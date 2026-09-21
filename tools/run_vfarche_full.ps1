[CmdletBinding()]
param(
    [string]$Master = "data/processed/cve_to_vf_evaluation.jsonl",
    [string]$OutDir = "results/evaluation/vfarche_full",
    [string]$PythonBin = "",

    [ValidateSet("pairwise", "chat", "embedding")]
    [string]$Rerank = "pairwise",

    [ValidateSet("auto", "tracker", "codebert", "bm25")]
    [string]$CandidateSelection = "auto",

    [string]$CodeBertCheckpoint = "",
    [int]$Limit = 0,
    [switch]$SkipDescriptionExpansion,
    [switch]$SkipMongoStart,
    [switch]$SkipDoctor,
    [switch]$SkipMetrics,
    [switch]$NoResume,
    [switch]$StopOnError,
    [switch]$Bootstrap,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$composeFile = Join-Path $repoRoot "configs/evaluation/vfarche/docker-compose.yml"
$envFile = Join-Path $repoRoot ".env"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    Write-Host "`n==> $Label" -ForegroundColor Cyan
    Write-Host ("    {0} {1}" -f $Command, ($Arguments -join " "))
    if ($DryRun) {
        return
    }

    Push-Location $WorkingDirectory
    try {
        & $Command @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Label failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

function Wait-ForMongo {
    param(
        [string]$HostName = "127.0.0.1",
        [int]$Port = 27017,
        [int]$TimeoutSeconds = 60
    )

    if ($DryRun) {
        return
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync($HostName, $Port)
            if ($task.Wait(1000) -and $client.Connected) {
                Write-Host "MongoDB is ready at ${HostName}:$Port." -ForegroundColor Green
                return
            }
        }
        catch {
            # MongoDB may still be starting.
        }
        finally {
            $client.Dispose()
        }
        Start-Sleep -Seconds 2
    }

    throw "MongoDB did not become reachable at ${HostName}:$Port within $TimeoutSeconds seconds."
}

$masterPath = if ([System.IO.Path]::IsPathRooted($Master)) {
    $Master
}
else {
    Join-Path $repoRoot $Master
}
if (-not (Test-Path -LiteralPath $masterPath -PathType Leaf)) {
    throw "Master dataset not found: $masterPath"
}
$Master = (Resolve-Path -LiteralPath $masterPath).Path

if (-not [System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path $repoRoot $OutDir
}

if (-not (Test-Path -LiteralPath $envFile)) {
    throw "Missing $envFile. Copy the repository-root .env.example to .env and configure it first."
}

$venvRoot = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvRoot "Scripts/python.exe"

if ($Bootstrap) {
    $uvCommand = Get-Command "uv" -ErrorAction SilentlyContinue
    if (-not $uvCommand) {
        throw "Bootstrap requires uv, but the 'uv' command was not found."
    }

    # Keep uv's cache inside the writable project instead of the user profile.
    $env:UV_CACHE_DIR = Join-Path $repoRoot ".uv-cache"
    Invoke-Checked `
        -Label "Create Python 3.11 virtual environment" `
        -Command $uvCommand.Path `
        -Arguments @("venv", $venvRoot, "--python", "3.11") `
        -WorkingDirectory $repoRoot
    Invoke-Checked `
        -Label "Install VFArCHE dependencies" `
        -Command $uvCommand.Path `
        -Arguments @(
            "pip", "install", "--python", $venvPython,
            "-r", (Join-Path $repoRoot "configs/evaluation/requirements/vfarche.txt"),
            "-r", (Join-Path $repoRoot "configs/evaluation/requirements/harness.txt")
        ) `
        -WorkingDirectory $repoRoot
    $PythonBin = $venvPython
}
elseif (-not $PythonBin) {
    if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
        $PythonBin = $venvPython
    }
    else {
        $pythonCommand = Get-Command "python" -ErrorAction SilentlyContinue
        if ($pythonCommand -and $pythonCommand.Path -notlike "*\Microsoft\WindowsApps\*") {
            $PythonBin = $pythonCommand.Path
        }
        elseif ($DryRun) {
            $PythonBin = "python"
        }
        else {
            throw "No usable Python runtime found. Re-run this script with -Bootstrap to create .venv using uv."
        }
    }
}

if (-not $SkipMongoStart) {
    Invoke-Checked `
        -Label "Start VFArCHE MongoDB" `
        -Command "docker" `
        -Arguments @("compose", "-f", $composeFile, "up", "-d", "mongo") `
        -WorkingDirectory $repoRoot
    Wait-ForMongo
}

if (-not $SkipDoctor) {
    Invoke-Checked `
        -Label "Check VFArCHE environment" `
        -Command $PythonBin `
        -Arguments @("-m", "pyshare.evaluation.cli", "doctor", "--methods", "vfarche") `
        -WorkingDirectory $repoRoot
}

# The closest implemented mode to the VFArCHE paper is query expansion plus
# pairwise reranking. Candidate-selection auto chooses Tracker for PATCH-PRESENT
# records and a fine-tuned CodeBERT checkpoint for PATCH-ABSENT records.
$env:VFARCHE_RERANK = $Rerank
$env:VFARCHE_SELECTION = $CandidateSelection
$env:VFARCHE_RESUME = if ($NoResume) { "0" } else { "1" }
$env:VFARCHE_CONTINUE_ON_ERROR = if ($StopOnError) { "0" } else { "1" }

if ($SkipDescriptionExpansion) {
    Remove-Item Env:VFARCHE_EXPAND -ErrorAction SilentlyContinue
}
else {
    $env:VFARCHE_EXPAND = "1"
}

if ($CodeBertCheckpoint) {
    $checkpointPath = $CodeBertCheckpoint
    if (-not [System.IO.Path]::IsPathRooted($checkpointPath)) {
        $checkpointPath = Join-Path $repoRoot $checkpointPath
    }
    if (-not (Test-Path -LiteralPath $checkpointPath)) {
        throw "CodeBERT checkpoint not found: $checkpointPath"
    }
    $env:VFARCHE_CODEBERT_CHECKPOINT = (Resolve-Path $checkpointPath).Path
}
elseif (-not $env:VFARCHE_CODEBERT_CHECKPOINT) {
    Write-Warning "No CodeBERT checkpoint configured. PATCH-ABSENT records will use the documented BM25 fallback."
}

$runArgs = @(
    "-m", "pyshare.evaluation.cli", "run",
    "--methods", "vfarche",
    "--master", $Master,
    "--out-dir", $OutDir,
    "--python-bin", $PythonBin
)
if ($Limit -gt 0) {
    $runArgs += @("--limit", $Limit.ToString())
}

Invoke-Checked `
    -Label "Run full VFArCHE pipeline" `
    -Command $PythonBin `
    -Arguments $runArgs `
    -WorkingDirectory $repoRoot

Invoke-Checked `
    -Label "Validate normalized predictions" `
    -Command $PythonBin `
    -Arguments @(
        "-m", "pyshare.evaluation.cli", "validate",
        "--pred-dir", $OutDir,
        "--master", $Master
    ) `
    -WorkingDirectory $repoRoot

if (-not $SkipMetrics) {
    Invoke-Checked `
        -Label "Compute VFArCHE metrics" `
        -Command $PythonBin `
        -Arguments @(
            "-m", "pyshare.evaluation.cli", "metrics",
            "--pred-dir", $OutDir,
            "--master", $Master
        ) `
        -WorkingDirectory $repoRoot
}

Write-Host "`nVFArCHE full run completed." -ForegroundColor Green
Write-Host "Predictions and metrics: $OutDir"
Write-Host "Per-CVE failure log: $(Join-Path $OutDir 'logs/vfarche_failures.jsonl')"
