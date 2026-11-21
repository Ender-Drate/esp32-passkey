# Flash the ESP32 Passkey firmware through its native USB port.
#
# The native USB connector has no auto-reset circuit, so put the board in ROM
# download mode by hand: hold BOOT, tap RST, release BOOT. Then run this
# script with the COM port that appeared (or leave -Port empty to list ports).

param(
    [string]$Port = "",
    [int]$WaitSeconds = 180
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$firmware = Join-Path $root "firmware"
$pkdev = Join-Path $root "scripts\pkdev.py"

$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $py) { throw "找不到 Python，请先安装 Python 3.11+ 与 PlatformIO" }

function Get-EspPorts {
    $out = & $py $pkdev ports 2>$null
    return @($out | Where-Object { $_ -match '^COM\d+$' })
}

if (-not $Port) {
    Write-Host "== TechXPassKey flasher ==" -ForegroundColor Cyan
    Write-Host "1) 按住 BOOT，点一下 RST，松开 BOOT"
    Write-Host "2) 等待下载模式出现（最多 $WaitSeconds 秒）"
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $before = @(Get-EspPorts)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 700
        $now = @(Get-EspPorts)
        $new = @($now | Where-Object { $before -notcontains $_ })
        if ($new.Count -gt 0) { $Port = $new[0]; break }
        if ($now.Count -eq 1 -and $before.Count -eq 0) { $Port = $now[0]; break }
    }
    if (-not $Port) {
        Write-Host "没有检测到新串口。当前串口：" -ForegroundColor Yellow
        Get-EspPorts | ForEach-Object { Write-Host "  $_" }
        $Port = Read-Host "请输入下载模式的 COM 口（例如 COM7）"
    }
}

Write-Host "烧录到 $Port ..." -ForegroundColor Cyan
& $py -m platformio run -d $firmware -t upload --upload-port $Port
if ($LASTEXITCODE -ne 0) { throw "烧录失败" }

Write-Host "等待设备启动 ..." -ForegroundColor Yellow
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 500
    $info = & $py $pkdev info 2>$null
    if ($LASTEXITCODE -eq 0 -and $info) {
        Write-Host "设备已启动：" -ForegroundColor Green
        $info
        exit 0
    }
}
Write-Host "已烧录，但管理接口未响应；请按一下 RST 再试。" -ForegroundColor Yellow
exit 2
