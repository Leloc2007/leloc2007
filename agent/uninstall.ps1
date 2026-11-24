# KidGuard - gỡ cài đặt khỏi laptop của con (chạy bằng PowerShell quyền Admin).
# Cách chạy:  irm http://<IP-máy-bố-mẹ>:8765/uninstall | iex
#        hoặc: powershell -ExecutionPolicy Bypass -File "C:\ProgramData\KidGuard\uninstall.ps1"
# Việc trả lại cài đặt mạng / trình duyệt do agent.ps1 -Cleanup làm (dùng chung code với lúc áp dụng).
& {
$ErrorActionPreference = 'Continue'
$Dir = Join-Path $env:ProgramData 'KidGuard'
$TaskPath = '\KidGuard\'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Cần chạy PowerShell bằng quyền Admin.' -ForegroundColor Red; return }

# 1. Dừng phần mềm
Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-ScheduledTask -InputObject $_ -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -InputObject $_ -Confirm:$false
}
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*KidGuard\agent.ps1*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# 2. Mở lại Internet, bỏ chặn web, trả DNS và trình duyệt về như cũ
$agent = Join-Path $Dir 'agent.ps1'
if (Test-Path $agent) {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $agent -Cleanup -Dir $Dir
} else {
    Write-Host "Không thấy $agent nên bỏ qua bước trả lại cài đặt." -ForegroundColor Yellow
}

# 3. Xóa thư mục
Remove-Item $Dir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Đã gỡ KidGuard và mở lại toàn bộ Internet trên máy này.' -ForegroundColor Green
}
