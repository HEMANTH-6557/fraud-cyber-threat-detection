$ErrorActionPreference = "Continue"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

Write-Host "Project Root: $projectRoot"

function Test-Port8501 {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect("127.0.0.1", 8501)
        $connected = $client.Connected
        $client.Close()
        return $connected
    } catch {
        return $false
    }
}

# 1. Check if port 8501 is active
if (-not (Test-Port8501)) {
    Write-Host "[1/3] Starting Streamlit server on http://127.0.0.1:8501..."
    $stProcess = Start-Process -FilePath "$projectRoot\.venv\Scripts\streamlit.exe" -ArgumentList "run", "dashboard\app.py", "--server.port", "8501", "--server.headless", "true" -WorkingDirectory $projectRoot -PassThru -WindowStyle Hidden
    
    $ready = $false
    for ($i = 0; $i -lt 25; $i++) {
        Start-Sleep -Seconds 1
        if (Test-Port8501) {
            $ready = $true
            break
        }
    }
    if ($ready) {
        Write-Host "[1/3] Streamlit is active on port 8501."
    } else {
        Write-Host "[WARNING] Streamlit did not respond on 8501 within 25s, proceeding..."
    }
} else {
    Write-Host "[1/3] Streamlit is already active on port 8501."
}

# 2. Stop existing cloudflared
Get-Process -Name "cloudflared" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$logFile = "$projectRoot\tunnel.log"
if (Test-Path $logFile) {
    Remove-Item $logFile -Force
}

# 3. Launch Cloudflared
Write-Host "[2/3] Starting Cloudflare Tunnel..."
$cfProcess = Start-Process -FilePath "$projectRoot\tools\cloudflared.exe" -ArgumentList "tunnel", "--url", "http://127.0.0.1:8501" -RedirectStandardError $logFile -RedirectStandardOutput "$projectRoot\tunnel.out" -WorkingDirectory $projectRoot -PassThru -WindowStyle Hidden

Write-Host "[3/3] Waiting for public HTTPS tunnel URL..."
$tunnelUrl = $null
for ($i = 0; $i -lt 35; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Path $logFile) {
        $content = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
        if ($content -match "(https://[-a-zA-Z0-9]+\.trycloudflare\.com)") {
            $tunnelUrl = $matches[1]
            break
        }
    }
}

if ($tunnelUrl) {
    Write-Host ""
    Write-Host "================================================================="
    Write-Host ">>> PUBLIC URL: $tunnelUrl <<<"
    Write-Host "================================================================="
    Write-Host ""
    Set-Content -Path "$projectRoot\public_url.txt" -Value $tunnelUrl
} else {
    Write-Host "[ERROR] Could not retrieve tunnel URL. Last log content:"
    if (Test-Path $logFile) {
        Get-Content $logFile -Tail 25
    }
}
