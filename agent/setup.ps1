# KidGuard - cài đặt lên laptop của con.
# Cách chạy (PowerShell quyền Admin):  irm http://<IP-máy-bố-mẹ>:8765/setup | iex
& {
$ErrorActionPreference = 'Stop'
$Base = '{{BASE}}'
$Alt = '{{ALT}}'
$Dir = Join-Path $env:ProgramData 'KidGuard'
$TaskPath = '\KidGuard\'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Cần chạy PowerShell bằng quyền Admin (chuột phải Start -> Terminal (Admin)).' -ForegroundColor Red
    return
}

Write-Host ''
Write-Host '=== Cài đặt KidGuard cho máy của con ===' -ForegroundColor Cyan
Write-Host "Máy bố mẹ: $Base"
$code = (Read-Host 'Nhập mã cài đặt 6 số hiện trên trang quản lý').Trim()

# 1. Đăng ký máy với máy bố mẹ
$body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress @{ code = $code; id = $env:COMPUTERNAME }))
try {
    $reg = Invoke-RestMethod -Uri "$Base/api/agent/enroll" -Method Post -Body $body -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec 10
} catch {
    Write-Host "Đăng ký thất bại: $($_.ErrorDetails.Message) $($_.Exception.Message)" -ForegroundColor Red
    return
}

# 2. Chép phần mềm
Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Dir | Out-Null
foreach ($f in 'agent.ps1', 'notify.ps1', 'uninstall.ps1') {
    $txt = (Invoke-WebRequest -Uri "$Base/agent/$f" -UseBasicParsing -TimeoutSec 15).Content
    if ($f -eq 'uninstall.ps1') { $txt = $txt.Replace('{{BASE}}', $Base).Replace('{{ALT}}', $Alt) }
    try { Set-Content -Path (Join-Path $Dir $f) -Value $txt -Encoding UTF8 }
    catch {
        # File gỡ cài đặt không bắt buộc: nếu bị chặn thì vẫn gỡ được bằng lệnh irm .../uninstall | iex
        if ($f -eq 'uninstall.ps1') { Write-Host "Lưu ý: không lưu được file gỡ cài đặt ($($_.Exception.Message)). Vẫn tiếp tục cài." -ForegroundColor Yellow; continue }
        Write-Host "Không lưu được $f : $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'Nếu Windows Security báo virus: mở Windows Security -> Protection history -> chọn mục KidGuard -> Allow, rồi chạy lại lệnh cài.' -ForegroundColor Yellow
        return
    }
}
$cfg = @{ controllers = @($Base, $Alt) | Select-Object -Unique; id = $reg.id; key = $reg.key }
$cfgFile = Join-Path $Dir 'agent.json'
[IO.File]::WriteAllText($cfgFile, (ConvertTo-Json $cfg), (New-Object Text.UTF8Encoding $false))

# 3. Phân quyền: con (Users) chỉ được đọc thư mục, không được đọc khóa bí mật
& icacls.exe $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
& icacls.exe $cfgFile /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null

# 4. Bắt trình duyệt dùng DNS của Windows (để lệnh chặn web không bị vượt qua)
foreach ($p in 'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge') {
    New-Item -Path $p -Force | Out-Null
    Set-ItemProperty -Path $p -Name 'DnsOverHttpsMode' -Value 'off' -Type String
}
$ff = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'
New-Item -Path $ff -Force | Out-Null
Set-ItemProperty -Path $ff -Name 'Enabled' -Value 0 -Type DWord
Set-ItemProperty -Path $ff -Name 'Locked' -Value 1 -Type DWord

# 5. Tạo các tác vụ chạy nền
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskPath $TaskPath -TaskName 'KidGuard-Agent' -Force -Settings $set `
    -Action (New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Dir\agent.ps1`"") `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) `
    -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) | Out-Null

$usersGroup = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value
$userPr = New-ScheduledTaskPrincipal -GroupId $usersGroup -RunLevel Limited
$uiSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances Parallel
Register-ScheduledTask -TaskPath $TaskPath -TaskName 'KidGuard-Lock' -Force -Principal $userPr -Settings $uiSet `
    -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\rundll32.exe" -Argument 'user32.dll,LockWorkStation') | Out-Null
Register-ScheduledTask -TaskPath $TaskPath -TaskName 'KidGuard-Notify' -Force -Principal $userPr -Settings $uiSet `
    -Action (New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Dir\notify.ps1`"") | Out-Null

Start-ScheduledTask -TaskPath $TaskPath -TaskName 'KidGuard-Agent'

Write-Host ''
Write-Host "Xong! Máy '$($reg.id)' đã được thêm vào trang quản lý." -ForegroundColor Green

# 6. Nhắc kiểm tra tài khoản Admin
$admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\')[-1] })
Write-Host ''
Write-Host "Các tài khoản có quyền Admin trên máy này: $($admins -join ', ')" -ForegroundColor Yellow
Write-Host 'QUAN TRỌNG: tài khoản của con phải là Standard (không phải Admin), nếu không con có thể gỡ phần mềm.' -ForegroundColor Yellow
Write-Host 'Đổi tại: Settings -> Accounts -> Other users -> chọn tài khoản của con -> Change account type -> Standard User.'
}
