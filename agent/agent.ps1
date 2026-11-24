#requires -Version 5.1
<#
  KidGuard agent - chạy trên laptop của con dưới quyền SYSTEM (Task Scheduler).
  Mỗi 10 giây: báo trạng thái về máy bố mẹ, nhận cài đặt + lệnh, rồi áp dụng:
    - Chặn / mở Internet (Windows Firewall, vẫn cho phép mạng nội bộ)
    - Chặn trang web (file hosts)
    - Lọc web người lớn (DNS Cloudflare for Families)
    - Khóa màn hình, gửi tin nhắn, tắt / khởi động lại máy
    - Chống lách (v1.1): tắt ẩn danh / khách trên trình duyệt, chặn cài tiện ích,
      tắt Opera / Brave / Tor / ứng dụng VPN, chặn trang tải các phần mềm đó
    - Tự cập nhật khi máy bố mẹ có phiên bản mới (v1.1)
    - Lịch dùng mạng theo từng ngày trong tuần (v1.2)
  -DryRun: chỉ ghi log, không thay đổi gì trên máy (dùng để thử).
#>
param(
    [switch]$DryRun,
    [switch]$Once,
    [switch]$Cleanup,   # dùng khi gỡ cài đặt: mở lại Internet, bỏ chặn, trả DNS và trình duyệt về như cũ rồi thoát
    [string]$Dir = "$env:ProgramData\KidGuard"
)
$ErrorActionPreference = 'Stop'
$Version = '1.2'
$ConfigFile = Join-Path $Dir 'agent.json'
$CacheFile = Join-Path $Dir 'cache.json'
$LogFile = Join-Path $Dir 'agent.log'
$MessageFile = Join-Path $Dir 'message.txt'
$RuleName = 'KidGuard-BlockInternet'
$TaskPath = '\KidGuard\'
$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$SafeDns = @('1.1.1.3', '1.0.0.3', '2606:4700:4700::1113', '2606:4700:4700::1003')
# Mọi địa chỉ Internet công cộng; chừa lại mạng nội bộ (10.x, 172.16-31.x, 192.168.x) để vẫn liên lạc được với máy bố mẹ.
$BlockRanges = @('1.0.0.0-9.255.255.255', '11.0.0.0-172.15.255.255', '172.32.0.0-192.167.255.255', '192.169.0.0-223.255.255.255', '2000::-3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
$HostsBegin = '# >>> KidGuard BEGIN - khong sua phan nay'
$HostsEnd = '# <<< KidGuard END'

# ---------- chống lách ----------
# Trang tải trình duyệt có VPN / Tor và phần mềm VPN phổ biến (file hosts không chặn tên miền con, nên liệt kê cụ thể).
$BypassHosts = @(
    'opera.com', 'download.opera.com', 'get.geo.opera.com', 'net.geo.opera.com', 'download3.operacdn.com', 'operacdn.com',
    'brave.com', 'laptop-updates.brave.com', 'referrals.brave.com', 'brave-browser-downloads.s3.brave.com',
    'torproject.org', 'dist.torproject.org', 'archive.torproject.org',
    'psiphon.ca', 'psiphon3.com', 'windscribe.com', 'assets.windscribe.com', 'protonvpn.com', 'tunnelbear.com',
    'hotspotshield.com', 'urban-vpn.com', 'xvpn.io', 'freevpnplanet.com', 'hola.org', 'ultrasurf.us',
    'vpnbook.com', 'hide.me', 'hidemyass.com', 'betternet.co', 'touchvpn.net', 'one.one.one.one'
)
# Tên tiến trình (không có .exe, viết thường) -> tên hiển thị
$BypassNames = @{
    'opera' = 'Opera'; 'opera_gx' = 'Opera GX'; 'brave' = 'Brave'; 'tor' = 'Tor'
    'psiphon3' = 'Psiphon'; 'psiphon' = 'Psiphon'; 'windscribe' = 'Windscribe'; 'protonvpn' = 'Proton VPN'; 'protonvpn.client' = 'Proton VPN'
    'tunnelbear' = 'TunnelBear'; 'hsscp' = 'Hotspot Shield'; 'hotspotshield' = 'Hotspot Shield'; 'urbanvpn' = 'Urban VPN'
    'xvpn' = 'X-VPN'; 'hola' = 'Hola'; 'betternet' = 'Betternet'; 'touchvpn' = 'Touch VPN'; 'cloudflare warp' = 'Cloudflare WARP'
}
# Thư mục cài đặt của các phần mềm trên (bắt cả khi con đổi tên file)
$BypassPathRegex = '\\(Opera GX|Opera|BraveSoftware|Tor Browser|Psiphon[^\\]*|Windscribe|ProtonVPN|Proton\\VPN|TunnelBear|Hotspot Shield|Urban VPN[^\\]*|X-VPN|Planet VPN|Hola[^\\]*|Betternet|Touch VPN|Cloudflare WARP)\\'
# Chính sách trình duyệt: tắt ẩn danh, chế độ khách, chặn cài tiện ích (nhiều tiện ích VPN)
$PolicyItems = @(
    @{ Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'IncognitoModeAvailability'; Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'BrowserGuestModeEnabled'; Value = 0; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist'; Name = '1'; Value = '*'; Type = 'String' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'InPrivateModeAvailability'; Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'BrowserGuestModeEnabled'; Value = 0; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist'; Name = '1'; Value = '*'; Type = 'String' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'DisablePrivateBrowsing'; Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'ExtensionSettings'; Value = '{"*":{"installation_mode":"blocked"}}'; Type = 'String' }
)

function Write-Log([string]$m) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m"
    if ($DryRun -or $Once) { Write-Host $line }
    try {
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) { Move-Item $LogFile "$LogFile.old" -Force }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch {}
}
function Get-NowMs { [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }

# ---------- cấu hình ----------
$AgentCfg = $null
$script:Controllers = @()
if (-not $Cleanup) {
    $AgentCfg = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $script:Controllers = @($AgentCfg.controllers | Where-Object { $_ })
}
$script:Config = $null
$script:Offset = 0
$script:FakeBlocked = $false
if (Test-Path $CacheFile) {
    try {
        $c = Get-Content $CacheFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:Config = $c.config; $script:Offset = [long]$c.offset
    } catch { Write-Log "Không đọc được cache: $($_.Exception.Message)" }
}
function Save-Cache {
    $json = ConvertTo-Json -InputObject @{ config = $script:Config; offset = $script:Offset } -Depth 8
    [IO.File]::WriteAllText($CacheFile, $json, (New-Object Text.UTF8Encoding $false))
}

# ---------- tính trạng thái ----------
function Get-Effective($c) {
    if ($null -eq $c) { return @{ allowed = $true; reason = 'noconfig' } }
    $now = (Get-NowMs) + $script:Offset
    if (($c.mode -eq 'on' -or $c.mode -eq 'off') -and ([long]$c.until -eq 0 -or $now -lt [long]$c.until)) {
        return @{ allowed = ($c.mode -eq 'on'); reason = "manual-$($c.mode)" }
    }
    $s = $c.schedule
    if ($null -eq $s -or -not $s.enabled) { return @{ allowed = $true; reason = 'noschedule' } }
    $t = Get-Date
    $days = @($s.days | Where-Object { $_ })
    if ($days.Count -eq 7) {
        # v1.2: mỗi ngày một khung giờ, days[0] = Chủ nhật ... days[6] = Thứ 7
        $day = $days[[int]$t.DayOfWeek]; $a = [string]$day.start; $b = [string]$day.end
    }
    elseif ($t.DayOfWeek -eq [DayOfWeek]::Saturday -or $t.DayOfWeek -eq [DayOfWeek]::Sunday) { $a = [string]$s.weStart; $b = [string]$s.weEnd }
    else { $a = [string]$s.wdStart; $b = [string]$s.wdEnd }
    $cur = $t.ToString('HH:mm')
    if ($a -eq $b) { $in = $true }
    elseif ([string]::CompareOrdinal($a, $b) -lt 0) { $in = ([string]::CompareOrdinal($cur, $a) -ge 0 -and [string]::CompareOrdinal($cur, $b) -lt 0) }
    else { $in = ([string]::CompareOrdinal($cur, $a) -ge 0 -or [string]::CompareOrdinal($cur, $b) -lt 0) }
    $reason = 'schedule-out'; if ($in) { $reason = 'schedule-in' }
    return @{ allowed = $in; reason = $reason }
}

# ---------- áp dụng ----------
function Set-Internet([bool]$allowed) {
    if ($DryRun) {
        if ($script:FakeBlocked -eq $allowed) { Write-Log "[thử] Internet -> $(if ($allowed) {'MỞ'} else {'CHẶN'})"; $script:FakeBlocked = -not $allowed }
        return
    }
    $rule = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
    if (-not $allowed -and -not $rule) {
        New-NetFirewallRule -Name $RuleName -DisplayName 'KidGuard - Chan Internet' -Direction Outbound -Action Block `
            -RemoteAddress $BlockRanges -Profile Any | Out-Null
        Write-Log 'Đã CHẶN Internet'
        # ngắt các kết nối đang mở (game, video...) để lệnh chặn có hiệu lực ngay
        Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Restart-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
    }
    elseif ($allowed -and $rule) {
        Remove-NetFirewallRule -Name $RuleName
        Write-Log 'Đã MỞ Internet'
    }
}

function Set-BlockedSites($domains) {
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($d in @($domains)) {
        if ([string]$d -notmatch '^([a-z0-9-]+\.)+[a-z]{2,}$') { continue }
        foreach ($h in @($d, "www.$d")) { $lines.Add("0.0.0.0 $h"); $lines.Add(":: $h") }
    }
    $current = ''
    if (Test-Path $HostsFile) { $current = [IO.File]::ReadAllText($HostsFile) }
    $pattern = '(?s)\s*' + [regex]::Escape($HostsBegin) + '.*?' + [regex]::Escape($HostsEnd) + '[^\n]*\n?'
    $base = [regex]::Replace($current, $pattern, "`r`n").TrimEnd()
    $new = $base
    if ($lines.Count) { $new += "`r`n`r`n$HostsBegin`r`n" + ($lines -join "`r`n") + "`r`n$HostsEnd" }
    $new += "`r`n"
    if ($new -ne $current) {
        if ($DryRun) { Write-Log "[thử] Cập nhật hosts: $(@($domains).Count) trang bị chặn"; return }
        [IO.File]::WriteAllText($HostsFile, $new, [Text.Encoding]::ASCII)
        Clear-DnsClientCache
        Write-Log "Đã cập nhật danh sách chặn: $(@($domains) -join ', ')"
    }
}

function Set-SafeDns([bool]$on) {
    $changed = $false
    foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)) {
        $cur = @(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
        $isSafe = $cur -contains '1.1.1.3'
        if ($on -and -not $isSafe) {
            if ($DryRun) { Write-Log "[thử] Bật DNS an toàn cho $($a.Name)"; continue }
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $SafeDns; $changed = $true
        }
        elseif (-not $on -and $isSafe) {
            if ($DryRun) { Write-Log "[thử] Tắt DNS an toàn cho $($a.Name)"; continue }
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses; $changed = $true
        }
    }
    if ($changed) { Clear-DnsClientCache; Write-Log "DNS an toàn: $(if ($on) {'BẬT'} else {'TẮT'})" }
}

function Show-Notice([string]$text) {
    if ($DryRun) { Write-Log "[thử] Thông báo: $text"; return }
    [IO.File]::WriteAllText($MessageFile, $text, (New-Object Text.UTF8Encoding $true))
    Start-ScheduledTask -TaskPath $TaskPath -TaskName 'KidGuard-Notify' -ErrorAction SilentlyContinue
}

function Invoke-ParentCommand($c) {
    Write-Log "Lệnh: $($c.cmd) $($c.text)"
    if ($DryRun) { return }
    switch ([string]$c.cmd) {
        'lock' { Start-ScheduledTask -TaskPath $TaskPath -TaskName 'KidGuard-Lock' }
        'message' { Show-Notice ([string]$c.text) }
        'shutdown' { & shutdown.exe /s /t 60 /c 'Bo me da tat may. May se tat sau 60 giay.' }
        'restart' { & shutdown.exe /r /t 60 /c 'Bo me da yeu cau khoi dong lai. May se khoi dong lai sau 60 giay.' }
        'cancel' { & shutdown.exe /a }
    }
}

# ---------- chống lách ----------
$script:PendingBypass = ''
$script:LastBypassNotice = 0

function Set-AntiBypassPolicies([bool]$on) {
    $changed = 0
    foreach ($i in $PolicyItems) {
        $cur = $null
        try { $cur = (Get-ItemProperty -Path $i.Path -Name $i.Name -ErrorAction Stop).($i.Name) } catch {}
        if ($on -and "$cur" -ne "$($i.Value)") {
            if ($DryRun) { Write-Log "[thử] Đặt chính sách $($i.Path)\$($i.Name)"; continue }
            if (-not (Test-Path $i.Path)) { New-Item -Path $i.Path -Force | Out-Null }
            Set-ItemProperty -Path $i.Path -Name $i.Name -Value $i.Value -Type $i.Type
            $changed++
        }
        elseif (-not $on -and $null -ne $cur) {
            if ($DryRun) { Write-Log "[thử] Gỡ chính sách $($i.Path)\$($i.Name)"; continue }
            Remove-ItemProperty -Path $i.Path -Name $i.Name -ErrorAction SilentlyContinue
            $changed++
        }
    }
    if ($changed) { Write-Log "Chính sách trình duyệt chống lách: $(if ($on) {'BẬT'} else {'TẮT'})" }
}

function Stop-BypassApps {
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $label = $null
        $name = [string]$p.ProcessName
        if ($BypassNames.ContainsKey($name)) { $label = $BypassNames[$name] }
        else {
            $path = $null
            try { $path = $p.Path } catch {}
            if ($path -and $path -match $BypassPathRegex) { $label = $Matches[1] }
        }
        if (-not $label) { continue }
        if ($DryRun) { Write-Log "[thử] Sẽ tắt $name ($label)"; $hits.Add($label); continue }
        try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; $hits.Add($label) } catch {}
    }
    $uniq = @($hits | Select-Object -Unique)
    if ($uniq.Count) {
        $txt = $uniq -join ', '
        Write-Log "Đã tắt phần mềm lách: $txt"
        $script:PendingBypass = $txt
        if ((Get-NowMs) - $script:LastBypassNotice -gt 60000) {
            Show-Notice "Bố mẹ không cho phép dùng: $txt."
            $script:LastBypassNotice = Get-NowMs
        }
    }
}

# ---------- tự cập nhật ----------
$script:UpdateRetryAt = 0
function Update-Agent([string]$newVer) {
    if ((Get-NowMs) -lt $script:UpdateRetryAt) { return }
    $script:UpdateRetryAt = (Get-NowMs) + 3600000   # lỗi thì 1 giờ sau mới thử lại
    $base = @($script:Controllers)[0]
    try {
        $files = [ordered]@{}
        foreach ($f in 'agent.ps1', 'notify.ps1') { $files[$f] = (Invoke-WebRequest -Uri "$base/agent/$f" -UseBasicParsing -TimeoutSec 15).Content }
        $files['uninstall.ps1'] = (Invoke-WebRequest -Uri "$base/uninstall" -UseBasicParsing -TimeoutSec 15).Content
        if ($files['agent.ps1'] -notmatch [regex]::Escape("`$Version = '$newVer'")) { throw "bản tải về không phải phiên bản $newVer" }
        foreach ($f in $files.Keys) { if ([string]::IsNullOrWhiteSpace($files[$f])) { throw "tải $f bị rỗng" } }
    } catch { Write-Log "Không cập nhật được lên $newVer : $($_.Exception.Message)"; return }
    if ($DryRun -or $Once) { Write-Log "[thử] Có bản mới $newVer, bỏ qua cập nhật khi chạy thử"; return }
    foreach ($f in $files.Keys) {
        try { [IO.File]::WriteAllText((Join-Path $Dir $f), $files[$f], (New-Object Text.UTF8Encoding $true)) }
        catch { Write-Log "Không ghi được $f : $($_.Exception.Message)"; if ($f -eq 'agent.ps1') { return } }
    }
    Write-Log "Đã cập nhật agent $Version -> $newVer, khởi động lại"
    # Chạy bản mới ngay trong tác vụ đang chạy (không phụ thuộc việc khởi động lại tác vụ)
    $ps = (Get-Process -Id $PID).Path
    & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Dir 'agent.ps1') -Dir $Dir
    exit 0
}

# ---------- liên lạc với máy bố mẹ ----------
function Get-ConsoleUser {
    try { $u = (Get-CimInstance Win32_ComputerSystem).UserName; if ($u) { return ($u -split '\\')[-1] } } catch {}
    return ''
}
function Invoke-Checkin($eff) {
    $body = ConvertTo-Json -Compress -InputObject @{
        hostname = $env:COMPUTERNAME; user = (Get-ConsoleUser); internet = [bool]$eff.allowed; reason = $eff.reason; version = $Version
        bypass = $script:PendingBypass
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
    $lastErr = $null
    foreach ($base in @($script:Controllers)) {
        try {
            $t0 = Get-NowMs
            $r = Invoke-RestMethod -Uri "$base/api/agent/checkin" -Method Post -Body $bytes -UseBasicParsing -TimeoutSec 6 `
                -ContentType 'application/json; charset=utf-8' -Headers @{ 'X-Device-Id' = $AgentCfg.id; 'X-Device-Key' = $AgentCfg.key }
            $t1 = Get-NowMs
            $script:Offset = [long]$r.serverTime - [long](($t0 + $t1) / 2)
            # ưu tiên địa chỉ vừa kết nối được
            $script:Controllers = @($base) + @($script:Controllers | Where-Object { $_ -ne $base })
            $script:PendingBypass = ''
            return $r
        } catch { $lastErr = $_.Exception.Message }
    }
    throw "Không kết nối được máy bố mẹ: $lastErr"
}

# ---------- gỡ cài đặt ----------
if ($Cleanup) {
    $script:FakeBlocked = $true
    foreach ($step in @(
            { Set-Internet $true },
            { Set-BlockedSites @() },
            { Set-SafeDns $false },
            { Set-AntiBypassPolicies $false },
            {
                # chính sách tắt DNS-over-HTTPS do setup.ps1 đặt
                foreach ($p in 'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge') {
                    if (-not $DryRun) { Remove-ItemProperty -Path $p -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue }
                }
                if (-not $DryRun) { Remove-Item 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS' -Recurse -ErrorAction SilentlyContinue }
            })) {
        try { & $step } catch { Write-Host "Lỗi khi trả lại cài đặt: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    if (-not $DryRun) { Clear-DnsClientCache -ErrorAction SilentlyContinue }
    Write-Host 'Đã trả lại cài đặt mạng và trình duyệt.'
    exit 0
}

# ---------- vòng lặp chính ----------
Write-Log "KidGuard agent $Version khởi động (DryRun=$DryRun) - máy bố mẹ: $($script:Controllers -join ', ')"
$prevAllowed = $null
$lastErrLog = 0
while ($true) {
    try {
        $r = Invoke-Checkin (Get-Effective $script:Config)
        $script:Config = $r.config
        Save-Cache
        foreach ($c in @($r.commands)) { if ($c) { try { Invoke-ParentCommand $c } catch { Write-Log "Lỗi lệnh: $($_.Exception.Message)" } } }
        if ($r.agentVersion -and [string]$r.agentVersion -ne $Version) { Update-Agent ([string]$r.agentVersion) }
    } catch {
        # tránh ghi log lỗi mỗi 10 giây khi máy bố mẹ tắt
        if ((Get-NowMs) - $lastErrLog -gt 600000) { Write-Log $_.Exception.Message; $lastErrLog = Get-NowMs }
    }

    $eff = Get-Effective $script:Config
    try { Set-Internet ([bool]$eff.allowed) } catch { Write-Log "Lỗi chặn Internet: $($_.Exception.Message)" }
    if ($null -ne $prevAllowed -and $prevAllowed -ne $eff.allowed) {
        if ($eff.allowed) { Show-Notice 'Internet đã được mở lại.' }
        elseif ($eff.reason -eq 'schedule-out') { Show-Notice 'Đã hết giờ dùng Internet theo lịch của bố mẹ.' }
        else { Show-Notice 'Bố mẹ đã tạm tắt Internet.' }
    }
    $prevAllowed = $eff.allowed

    $sites = @(); $safe = $false; $anti = $true
    if ($script:Config) {
        $sites = @($script:Config.blockedSites | Where-Object { $_ }); $safe = [bool]$script:Config.safeDns
        if ($null -ne $script:Config.antiBypass) { $anti = [bool]$script:Config.antiBypass }
    }
    if ($anti) { $sites = @($sites) + $BypassHosts | Select-Object -Unique }
    try { Set-BlockedSites $sites } catch { Write-Log "Lỗi cập nhật hosts: $($_.Exception.Message)" }
    try { Set-AntiBypassPolicies $anti } catch { Write-Log "Lỗi chính sách trình duyệt: $($_.Exception.Message)" }
    if ($anti) { try { Stop-BypassApps } catch { Write-Log "Lỗi chặn phần mềm lách: $($_.Exception.Message)" } }
    try { Set-SafeDns $safe } catch { Write-Log "Lỗi DNS: $($_.Exception.Message)" }

    if ($Once) { break }
    Start-Sleep -Seconds 10
}
