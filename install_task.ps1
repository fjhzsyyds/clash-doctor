# install_task.ps1 — 注册 clash-doctor 定时自愈计划任务
#
# 用法（管理员或普通用户均可，普通用户限当前用户任务）：
#   .\install_task.ps1                 # 每 30 分钟
#   .\install_task.ps1 -Interval 10    # 每 10 分钟
#   .\install_task.ps1 -Remove         # 卸载
#
# 脚本健康时开销极小：一次 HTTPS 探测即退出。

param(
    [int]$Interval = 30,
    [switch]$Remove,
    [string]$TaskName = "Clash Doctor"
)

$ErrorActionPreference = "Stop"

if ($Remove) {
    schtasks /delete /tn "$TaskName" /f 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Host "已卸载计划任务: $TaskName" }
    else { Write-Host "未找到计划任务: $TaskName" }
    exit 0
}

$script = Join-Path $PSScriptRoot "clash_doctor.py"
if (-not (Test-Path $script)) {
    Write-Error "找不到 clash_doctor.py: $script"
    exit 1
}

# 找 python
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $py) {
    Write-Error "找不到 python，请先安装 Python 3.8+"
    exit 1
}

# 用 pythonw 避免每次弹黑框（若存在）
$pyw = Join-Path (Split-Path $py) "pythonw.exe"
$exe = if (Test-Path $pyw) { $pyw } else { $py }

# 日志文件，方便回溯
$log = Join-Path $env:LOCALAPPDATA "clash-doctor.log"
$action = "`"$exe`" `"$script`" >> `"$log`" 2>&1"

Write-Host "Python : $exe"
Write-Host "脚本   : $script"
Write-Host "间隔   : 每 $Interval 分钟"
Write-Host "日志   : $log"

schtasks /create /tn "$TaskName" /sc minute /mo $Interval `
    /tr "$action" /f | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✓ 计划任务已创建: $TaskName"
    Write-Host "  查看: schtasks /query /tn `"$TaskName`""
    Write-Host "  卸载: .\install_task.ps1 -Remove"
} else {
    Write-Error "创建计划任务失败（可能需要管理员权限）"
    exit 1
}
