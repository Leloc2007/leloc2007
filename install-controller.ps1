# KidGuard - cài trang quản lý lên laptop của BỐ MẸ.
# Cách chạy: chuột phải file "Cai-dat-may-bo-me.cmd" -> Run as administrator
#   (hoặc PowerShell Admin: powershell -ExecutionPolicy Bypass -File install-controller.ps1)
param([int]$Port = 8765)
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Cần chạy bằng quyền Admin (chuột phải -> Run as administrator).' -ForegroundColor Red; Read-Host 'Bấm Enter để thoát'; exit 1 }

$Dest = Join-Path $env:LOCALAPPDATA 'KidGuard'
$DataDir = Join-Path $Dest 'controller\data'
$StateFile = Join-Path $DataDir 'state.json'
$User = "$env:USERDOMAIN\$env:USERNAME"

Write-Host ''
Write-Host '=== Cài đặt trang quản lý máy của con ===' -ForegroundColor Cyan

# 1. Chép chương trình vào thư mục cố định
Get-ScheduledTask -TaskPath '\KidGuard\' -TaskName 'KidGuard-Controller' -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*KidGuard\controller\controller.ps1*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force (Join-Path $Dest 'controller'), (Join-Path $Dest 'agent'), $DataDir | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'controller\controller.ps1'), (Join-Path $PSScriptRoot 'controller\dashboard.html') (Join-Path $Dest 'controller') -Force
Copy-Item (Join-Path $PSScriptRoot 'agent\*.ps1') (Join-Path $Dest 'agent') -Force

# 2. Mật khẩu trang quản lý
$setPw = $true
if (Test-Path $StateFile) { $setPw = (Read-Host 'Đã có mật khẩu cũ. Đặt mật khẩu mới? (c/k)') -match '^[cCyY]' }
if ($setPw) {
    while ($true) {
        $p1 = Read-Host 'Đặt mật khẩu cho trang quản lý (ít nhất 6 ký tự)' -AsSecureString
        $p2 = Read-Host 'Nhập lại mật khẩu' -AsSecureString
        $t1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
        $t2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))
        if ($t1.Length -lt 6) { Write-Host 'Mật khẩu quá ngắn.' -ForegroundColor Yellow; continue }
        if ($t1 -ne $t2) { Write-Host 'Hai lần nhập không khớp.' -ForegroundColor Yellow; continue }
        break
    }
    $b = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    $salt = ([BitConverter]::ToString($b) -replace '-', '').ToLower()
    $hash = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($salt + $t1))) -replace '-', '').ToLower()
    if (Test-Path $StateFile) { $state = Get-Content $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json } else { $state = [pscustomobject]@{ devices = [pscustomobject]@{} } }
    $state | Add-Member -Force NoteProperty salt $salt
    $state | Add-Member -Force NoteProperty passwordHash $hash
    $state | Add-Member -Force NoteProperty sessions ([pscustomobject]@{})   # đăng xuất mọi nơi
    [IO.File]::WriteAllText($StateFile, (ConvertTo-Json $state -Depth 10), (New-Object Text.UTF8Encoding $false))
}
# chỉ tài khoản này (và hệ thống) được đọc dữ liệu
& icacls.exe $DataDir /inheritance:r /grant:r "${User}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

# 3. Cho phép mở cổng web và cho máy trong mạng nhà kết nối tới
& netsh.exe http delete urlacl url="http://+:$Port/" 2>$null | Out-Null
& netsh.exe http add urlacl url="http://+:$Port/" user="$User" | Out-Null
Remove-NetFirewallRule -Name 'KidGuard-Controller' -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'KidGuard-Controller' -DisplayName 'KidGuard - Trang quan ly' -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort $Port -RemoteAddress LocalSubnet -Profile Any | Out-Null

# 4. Tự chạy khi bố mẹ đăng nhập máy
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskPath '\KidGuard\' -TaskName 'KidGuard-Controller' -Force -Settings $set `
    -Action (New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Dest\controller\controller.ps1`" -Port $Port") `
    -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $User) `
    -Principal (New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited) | Out-Null
Start-ScheduledTask -TaskPath '\KidGuard\' -TaskName 'KidGuard-Controller'

# 5. Lối tắt trên Desktop
$desktop = [Environment]::GetFolderPath('Desktop')
Set-Content -Path (Join-Path $desktop 'Quan ly may cua con.url') -Value "[InternetShortcut]`r`nURL=http://localhost:$Port/" -Encoding ASCII

$ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -in 'Dhcp', 'Manual' } | ForEach-Object IPAddress)
Write-Host ''
Write-Host 'Xong! Trang quản lý đã chạy.' -ForegroundColor Green
Write-Host "  - Trên máy này: http://localhost:$Port  (có lối tắt 'Quan ly may cua con' trên Desktop)"
foreach ($ip in $ips) { Write-Host "  - Từ điện thoại cùng wifi: http://${ip}:$Port" }
Write-Host ''
Write-Host 'Tiếp theo: mở trang quản lý -> bấm "+ Thêm máy của con" và làm theo hướng dẫn.'
Start-Process "http://localhost:$Port/"
Read-Host 'Bấm Enter để đóng'
