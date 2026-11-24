# KidGuard - hiện thông báo cho người đang dùng máy (chạy trong phiên của con).
$file = Join-Path $env:ProgramData 'KidGuard\message.txt'
if (-not (Test-Path $file)) { return }
$text = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8)
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show($text, 'Tin nhắn từ Bố Mẹ',
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information,
    [System.Windows.Forms.MessageBoxDefaultButton]::Button1,
    [System.Windows.Forms.MessageBoxOptions]::DefaultDesktopOnly) | Out-Null
