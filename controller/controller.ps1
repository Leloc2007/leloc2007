#requires -Version 5.1
<#
  KidGuard - may chu quan ly (chay tren laptop cua bo me).
  Phuc vu trang quan ly (dashboard.html) va nhan ket noi tu agent tren laptop cua con.
#>
param(
    [int]$Port = 8765,
    [switch]$LocalOnly,
    [string]$DataDir,
    # Noi dat ban moi (thu muc chua update.json). Trang quan ly tu kiem tra va tu cap nhat tu day.
    [string]$UpdateUrl = 'https://raw.githubusercontent.com/Leloc2007/leloc2007/kidguard'
)
$ErrorActionPreference = 'Stop'
$Version = '1.2'
if (-not $DataDir) { $DataDir = Join-Path $PSScriptRoot 'data' }
$StateFile = Join-Path $DataDir 'state.json'
$LogFile = Join-Path $DataDir 'controller.log'
$AgentDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'agent'
New-Item -ItemType Directory -Force $DataDir | Out-Null

# ---------- tien ich ----------
function Write-Log([string]$m) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m"
    Write-Host $line
    try {
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) { Move-Item $LogFile "$LogFile.old" -Force }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch {}
}
function Get-NowMs { [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }
function New-RandomToken([int]$bytes = 24) {
    $b = New-Object byte[] $bytes
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    ([BitConverter]::ToString($b) -replace '-', '').ToLower()
}
function Get-Sha256([string]$text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))) -replace '-', '').ToLower()
}
function ConvertTo-HT($o) {
    if ($null -eq $o) { return $null }
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        $h = [ordered]@{}
        foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = ConvertTo-HT $p.Value }
        return $h
    }
    if ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) {
        return , @($o | ForEach-Object { ConvertTo-HT $_ })
    }
    return $o
}
function Has-Prop($obj, [string]$name) { $null -ne $obj -and $null -ne $obj.PSObject.Properties[$name] }

# ---------- trang thai ----------
function Read-State {
    if (-not (Test-Path $StateFile)) { throw "Chua co file $StateFile. Hay chay install-controller.ps1 truoc." }
    $s = ConvertTo-HT (Get-Content $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json)
    if ($null -eq $s.devices) { $s.devices = [ordered]@{} }
    if ($null -eq $s.sessions) { $s.sessions = [ordered]@{} }
    # may them tu ban 1.0 / 1.1: lich chi co "ngay thuong / cuoi tuan" -> doi sang lich tung ngay
    foreach ($d in @($s.devices.Values)) {
        $sc = $d.schedule
        if ($null -ne $sc -and (-not $sc.Contains('days') -or @($sc.days).Count -ne 7)) {
            $sc['days'] = New-Days ([string]$sc.wdStart) ([string]$sc.wdEnd) ([string]$sc.weStart) ([string]$sc.weEnd)
        }
    }
    return $s
}
function Save-State {
    $json = ConvertTo-Json -InputObject $script:State -Depth 10
    $tmp = "$StateFile.tmp"
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding $false))
    Move-Item $tmp $StateFile -Force
}
# Lich tung ngay: days[0] = Chu nhat, days[1] = Thu 2 ... days[6] = Thu 7
function New-Days([string]$wdS, [string]$wdE, [string]$weS, [string]$weE) {
    if ($wdS -notmatch '^\d\d:\d\d$') { $wdS = '07:00' }; if ($wdE -notmatch '^\d\d:\d\d$') { $wdE = '21:30' }
    if ($weS -notmatch '^\d\d:\d\d$') { $weS = '08:00' }; if ($weE -notmatch '^\d\d:\d\d$') { $weE = '22:00' }
    return , @(0..6 | ForEach-Object {
            if ($_ -eq 0 -or $_ -eq 6) { [ordered]@{ start = $weS; end = $weE } } else { [ordered]@{ start = $wdS; end = $wdE } }
        })
}
function New-Device([string]$id, [string]$hostname) {
    [ordered]@{
        id = $id; name = $hostname; hostname = $hostname; key = ''
        ip = ''; user = ''; lastSeen = 0; internet = $null; reason = ''; version = ''
        mode = 'auto'; until = 0
        schedule = [ordered]@{ enabled = $true; days = (New-Days '07:00' '21:30' '08:00' '22:00'); wdStart = '07:00'; wdEnd = '21:30'; weStart = '08:00'; weEnd = '22:00' }
        blockedSites = @(); safeDns = $true; antiBypass = $true; lastBypass = ''; lastBypassAt = 0; commands = @()
    }
}
# máy thêm từ bản 1.0 chưa có trường antiBypass -> mặc định bật
function Get-AntiBypass($d) { if ($d.Contains('antiBypass')) { return [bool]$d.antiBypass } return $true }
function Get-PublicDevice($d) {
    $o = [ordered]@{}
    foreach ($k in $d.Keys) { if ($k -ne 'key') { $o[$k] = $d[$k] } }
    $o.antiBypass = Get-AntiBypass $d
    $o.online = ((Get-NowMs) - [long]$d.lastSeen) -lt 35000
    $o.pendingCommands = @($d.commands).Count
    return $o
}
function Get-CleanDomain([string]$s) {
    if (-not $s) { return $null }
    $s = $s.Trim().ToLower() -replace '^[a-z]+://', ''
    $s = ($s -split '[/?#:]')[0] -replace '^www\.', ''
    $s = $s.TrimEnd('.')
    if ($s -match '^(?=.{3,253}$)([a-z0-9-]+\.)+[a-z]{2,}$') { return $s }
    return $null
}
function Get-LanIPs {
    @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -in 'Dhcp', 'Manual' } |
        ForEach-Object { $_.IPAddress })
}

# ---------- HTTP ----------
function Send-Response($ctx, [int]$code, $obj, [string]$ctype = 'application/json; charset=utf-8') {
    if ($obj -is [string]) { $text = $obj } else { $text = ConvertTo-Json -InputObject $obj -Depth 10 -Compress }
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    $res = $ctx.Response
    $res.StatusCode = $code
    $res.ContentType = $ctype
    $res.Headers['Cache-Control'] = 'no-store'
    $res.ContentLength64 = $bytes.Length
    $res.OutputStream.Write($bytes, 0, $bytes.Length)
    $res.OutputStream.Close()
}
function Read-Body($req) {
    $sr = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)
    $t = $sr.ReadToEnd(); $sr.Close()
    if ([string]::IsNullOrWhiteSpace($t)) { return New-Object psobject }
    return ($t | ConvertFrom-Json)
}
function Test-Auth($req) {
    $tok = $req.Headers['X-Auth']
    if (-not $tok) { return $false }
    $exp = $script:State.sessions[$tok]
    return ($null -ne $exp -and [long]$exp -gt (Get-NowMs))
}
function Read-TextFile([string]$path) { [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8) }

# ---------- tu cap nhat ----------
$RootDir = Split-Path $PSScriptRoot -Parent
$script:Update = [ordered]@{ checkedAt = 0; status = 'chua kiem tra'; latest = '' }
$script:NextUpdateCheck = 0
$script:RestartPending = $false
function Get-UrlBytes([string]$url) {
    $rq = [Net.HttpWebRequest]::Create($url)
    $rq.Timeout = 8000; $rq.ReadWriteTimeout = 8000; $rq.UserAgent = "KidGuard/$Version"
    $rs = $rq.GetResponse()
    try { $ms = New-Object IO.MemoryStream; $rs.GetResponseStream().CopyTo($ms); return , $ms.ToArray() } finally { $rs.Close() }
}
# Tra ve $true neu da tai va chep ban moi (can khoi dong lai trang quan ly).
function Invoke-UpdateCheck {
    $now = Get-NowMs
    $script:NextUpdateCheck = $now + 6 * 3600000
    $script:Update.checkedAt = $now
    if (-not $UpdateUrl) { $script:Update.status = 'tat'; return $false }
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
        $base = $UpdateUrl.TrimEnd('/')
        $man = [Text.Encoding]::UTF8.GetString((Get-UrlBytes "$base/update.json")).TrimStart([char]0xFEFF) | ConvertFrom-Json
        $new = [string]$man.version
        $script:Update.latest = $new
        if ([version]$new -le [version]$Version) { $script:Update.status = 'moi nhat'; return $false }
        $sha = [Security.Cryptography.SHA256]::Create()
        $got = [ordered]@{}
        foreach ($f in @($man.files)) {
            $rel = [string]$f.path
            if ($rel -notmatch '^(controller|agent)/[A-Za-z0-9-]+\.(ps1|html)$') { throw "ten tep khong hop le: $rel" }
            $bytes = Get-UrlBytes "$base/$rel"
            $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLower()
            if ($hash -ne ([string]$f.sha256).ToLower()) { throw "tep $rel tai ve bi sai (khong khop ma kiem tra)" }
            $got[$rel] = $bytes
        }
        foreach ($need in 'controller/controller.ps1', 'agent/agent.ps1') {
            if (-not $got.Contains($need)) { throw "ban moi thieu tep $need" }
            if ([Text.Encoding]::UTF8.GetString($got[$need]) -notmatch [regex]::Escape("`$Version = '$new'")) { throw "tep $need khong phai phien ban $new" }
        }
        foreach ($rel in $got.Keys) { [IO.File]::WriteAllBytes((Join-Path $RootDir ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)), $got[$rel]) }
        $script:Update.status = "da cap nhat len $new"
        Write-Log "Da tai ban moi $new (dang chay $Version)"
        return $true
    } catch {
        $script:Update.status = "loi: $($_.Exception.Message)"
        $script:NextUpdateCheck = $now + 30 * 60000   # loi mang thi 30 phut sau thu lai
        Write-Log "Khong kiem tra duoc ban moi: $($_.Exception.Message)"
        return $false
    }
}
# Chay ban moi ngay trong tien trinh nay (tac vu Task Scheduler van giu nguyen).
function Start-NewVersion {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'controller.ps1'), '-Port', $Port, '-DataDir', $DataDir, '-UpdateUrl', $UpdateUrl)
    if ($LocalOnly) { $a += '-LocalOnly' }
    & (Get-Process -Id $PID).Path @a
    exit 0
}

$script:Enroll = @{ code = ''; expires = 0 }
$script:LoginFails = 0
$script:LoginLockUntil = 0

function Invoke-Route($ctx) {
    $req = $ctx.Request
    $path = $req.Url.AbsolutePath.TrimEnd('/')
    if ($path -eq '') { $path = '/' }
    $method = $req.HttpMethod
    $now = Get-NowMs

    # ----- tep tinh / script cai dat -----
    if ($method -eq 'GET' -and ($path -eq '/' -or $path -eq '/index.html')) {
        return Send-Response $ctx 200 (Read-TextFile (Join-Path $PSScriptRoot 'dashboard.html')) 'text/html; charset=utf-8'
    }
    if ($method -eq 'GET' -and ($path -eq '/setup' -or $path -eq '/uninstall')) {
        $base = "http://$($req.Url.Host):$($req.Url.Port)"
        $alt = "http://$($env:COMPUTERNAME):$Port"
        $file = if ($path -eq '/setup') { 'setup.ps1' } else { 'uninstall.ps1' }
        $txt = (Read-TextFile (Join-Path $AgentDir $file)).Replace('{{BASE}}', $base).Replace('{{ALT}}', $alt)
        return Send-Response $ctx 200 $txt 'text/plain; charset=utf-8'
    }
    if ($method -eq 'GET' -and $path -match '^/agent/(agent|notify|uninstall)\.ps1$') {
        return Send-Response $ctx 200 (Read-TextFile (Join-Path $AgentDir "$($Matches[1]).ps1")) 'text/plain; charset=utf-8'
    }

    # ----- agent -----
    if ($method -eq 'POST' -and $path -eq '/api/agent/enroll') {
        $b = Read-Body $req
        if (-not $script:Enroll.code -or $now -gt $script:Enroll.expires -or [string]$b.code -ne $script:Enroll.code) {
            Start-Sleep -Seconds 1
            return Send-Response $ctx 403 @{ error = 'Ma cai dat sai hoac da het han.' }
        }
        $id = ([string]$b.id).ToUpper()
        if ($id -notmatch '^[A-Z0-9._-]{1,63}$') { return Send-Response $ctx 400 @{ error = 'Ten may khong hop le.' } }
        $d = $script:State.devices[$id]
        if ($null -eq $d) { $d = New-Device $id $id; $script:State.devices[$id] = $d }
        $d.key = New-RandomToken
        Save-State
        Write-Log "Da them may $id"
        return Send-Response $ctx 200 @{ id = $id; key = $d.key }
    }
    if ($method -eq 'POST' -and $path -eq '/api/agent/checkin') {
        $id = [string]$req.Headers['X-Device-Id']
        $d = $null
        if ($id) { $d = $script:State.devices[$id.ToUpper()] }
        if ($null -eq $d -or -not $d.key -or $d.key -ne [string]$req.Headers['X-Device-Key']) {
            return Send-Response $ctx 401 @{ error = 'unauthorized' }
        }
        $b = Read-Body $req
        $d.lastSeen = $now
        $d.ip = [string]$req.RemoteEndPoint.Address
        foreach ($k in 'user', 'reason', 'version', 'hostname') { if (Has-Prop $b $k) { $d[$k] = [string]$b.$k } }
        if (Has-Prop $b 'internet') { $d.internet = [bool]$b.internet }
        if ((Has-Prop $b 'bypass') -and [string]$b.bypass) {
            $t = [string]$b.bypass; if ($t.Length -gt 100) { $t = $t.Substring(0, 100) }
            $d['lastBypass'] = $t; $d['lastBypassAt'] = $now
            Write-Log "May $($d.id): da chan phan mem lach $t"
        }
        # het han lenh tam thoi -> quay ve theo lich
        if ($d.mode -ne 'auto' -and [long]$d.until -gt 0 -and $now -gt [long]$d.until) { $d.mode = 'auto'; $d.until = 0 }
        $cmds = @($d.commands)
        $d.commands = @()
        Save-State
        return Send-Response $ctx 200 ([ordered]@{
                serverTime = $now
                config       = [ordered]@{ mode = $d.mode; until = $d.until; schedule = $d.schedule; blockedSites = @($d.blockedSites); safeDns = $d.safeDns; antiBypass = (Get-AntiBypass $d) }
                commands     = $cmds
                agentVersion = $Version
            })
    }

    # ----- dang nhap -----
    if ($method -eq 'POST' -and $path -eq '/api/login') {
        if ($now -lt $script:LoginLockUntil) { return Send-Response $ctx 429 @{ error = 'Nhap sai nhieu lan. Vui long doi 1 phut.' } }
        $b = Read-Body $req
        if ((Get-Sha256 ($script:State.salt + [string]$b.password)) -eq $script:State.passwordHash) {
            $script:LoginFails = 0
            $tok = New-RandomToken
            $script:State.sessions[$tok] = $now + 30L * 24 * 3600 * 1000
            # don phien het han
            foreach ($k in @($script:State.sessions.Keys)) { if ([long]$script:State.sessions[$k] -lt $now) { $script:State.sessions.Remove($k) } }
            Save-State
            return Send-Response $ctx 200 @{ token = $tok }
        }
        $script:LoginFails++
        if ($script:LoginFails -ge 5) { $script:LoginLockUntil = $now + 60000; $script:LoginFails = 0 }
        Start-Sleep -Seconds 1
        return Send-Response $ctx 401 @{ error = 'Sai mat khau.' }
    }

    if ($path -like '/api/*' -and -not (Test-Auth $req)) { return Send-Response $ctx 401 @{ error = 'Can dang nhap.' } }

    # ----- API cho bo me -----
    if ($method -eq 'GET' -and $path -eq '/api/devices') {
        $list = @($script:State.devices.Values | ForEach-Object { Get-PublicDevice $_ })
        return Send-Response $ctx 200 ([ordered]@{ serverTime = $now; devices = $list })
    }
    if ($method -eq 'GET' -and $path -eq '/api/info') {
        return Send-Response $ctx 200 ([ordered]@{ hostname = $env:COMPUTERNAME; port = $Port; ips = @(Get-LanIPs); version = $Version; update = $script:Update })
    }
    if ($method -eq 'POST' -and $path -eq '/api/update-check') {
        $done = Invoke-UpdateCheck
        if ($done) { $script:RestartPending = $true }
        return Send-Response $ctx 200 ([ordered]@{ updated = [bool]$done; version = $Version; update = $script:Update })
    }
    if ($method -eq 'POST' -and $path -eq '/api/enroll-code') {
        $script:Enroll.code = '{0:D6}' -f (Get-Random -Minimum 0 -Maximum 1000000)
        $script:Enroll.expires = $now + 30 * 60 * 1000
        return Send-Response $ctx 200 @{ code = $script:Enroll.code; expires = $script:Enroll.expires }
    }
    if ($path -match '^/api/devices/([A-Za-z0-9._-]+)(/command)?$') {
        $id = $Matches[1].ToUpper(); $isCmd = [bool]$Matches[2]
        $d = $script:State.devices[$id]
        if ($null -eq $d) { return Send-Response $ctx 404 @{ error = 'Khong tim thay may.' } }

        if ($method -eq 'DELETE' -and -not $isCmd) {
            $script:State.devices.Remove($id); Save-State
            return Send-Response $ctx 200 @{ ok = $true }
        }
        if ($method -eq 'POST' -and $isCmd) {
            $b = Read-Body $req
            $cmd = [string]$b.cmd
            if ($cmd -notin 'lock', 'message', 'shutdown', 'restart', 'cancel') { return Send-Response $ctx 400 @{ error = 'Lenh khong hop le.' } }
            $text = ([string]$b.text)
            if ($text.Length -gt 500) { $text = $text.Substring(0, 500) }
            $d.commands = @($d.commands) + @([ordered]@{ id = (New-RandomToken 6); cmd = $cmd; text = $text; at = $now })
            Save-State
            return Send-Response $ctx 200 @{ ok = $true }
        }
        if ($method -eq 'POST') {
            $b = Read-Body $req
            if (Has-Prop $b 'name') {
                $n = ([string]$b.name).Trim()
                if ($n.Length -gt 40) { $n = $n.Substring(0, 40) }
                if ($n) { $d.name = $n }
            }
            if (Has-Prop $b 'mode') {
                if ([string]$b.mode -notin 'auto', 'on', 'off') { return Send-Response $ctx 400 @{ error = 'Che do khong hop le.' } }
                $d.mode = [string]$b.mode
                $mins = 0; if (Has-Prop $b 'minutes') { $mins = [int]$b.minutes }
                if ($d.mode -ne 'auto' -and $mins -gt 0) { $d.until = $now + [long]$mins * 60000 } else { $d.until = 0 }
            }
            if (Has-Prop $b 'schedule') {
                $sc = $b.schedule
                if (Has-Prop $sc 'enabled') { $d.schedule.enabled = [bool]$sc.enabled }
                if (Has-Prop $sc 'days') {
                    $in = @($sc.days)
                    if ($in.Count -ne 7) { return Send-Response $ctx 400 @{ error = 'Lich phai co du 7 ngay.' } }
                    $new = @()
                    foreach ($x in $in) {
                        foreach ($k in 'start', 'end') {
                            if ([string]$x.$k -notmatch '^([01]\d|2[0-3]):[0-5]\d$') { return Send-Response $ctx 400 @{ error = "Gio khong hop le: $($x.$k)" } }
                        }
                        $new += [ordered]@{ start = [string]$x.start; end = [string]$x.end }
                    }
                    $d.schedule['days'] = $new
                    # giu truong cu cho may con chua kip cap nhat (Thu 2 va Thu 7 lam dai dien)
                    $d.schedule['wdStart'] = $new[1].start; $d.schedule['wdEnd'] = $new[1].end
                    $d.schedule['weStart'] = $new[6].start; $d.schedule['weEnd'] = $new[6].end
                }
            }
            if (Has-Prop $b 'blockedSites') {
                $d.blockedSites = @(@($b.blockedSites) | ForEach-Object { Get-CleanDomain ([string]$_) } | Where-Object { $_ } | Select-Object -Unique)
            }
            if (Has-Prop $b 'safeDns') { $d.safeDns = [bool]$b.safeDns }
            if (Has-Prop $b 'antiBypass') { $d['antiBypass'] = [bool]$b.antiBypass }
            Save-State
            return Send-Response $ctx 200 (Get-PublicDevice $d)
        }
    }
    return Send-Response $ctx 404 @{ error = 'Not found' }
}

# ---------- chay ----------
$script:State = Read-State
if (Invoke-UpdateCheck) { Start-NewVersion }
$listener = New-Object Net.HttpListener
if ($LocalOnly) { $listener.Prefixes.Add("http://localhost:$Port/") } else { $listener.Prefixes.Add("http://+:$Port/") }
$listener.Start()
Write-Log "KidGuard controller $Version dang chay tren cong $Port. Mo http://localhost:$Port de quan ly."
while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    try { Invoke-Route $ctx }
    catch {
        Write-Log "Loi: $($_.Exception.Message)"
        try { Send-Response $ctx 500 @{ error = $_.Exception.Message } } catch {}
    }
    # 6 gio kiem tra ban moi mot lan; co ban moi thi tu chep va chay lai
    if (-not $script:RestartPending -and (Get-NowMs) -gt $script:NextUpdateCheck) { $script:RestartPending = [bool](Invoke-UpdateCheck) }
    if ($script:RestartPending) {
        Write-Log 'Khoi dong lai trang quan ly voi ban moi'
        $listener.Stop(); $listener.Close()
        Start-NewVersion
    }
}
