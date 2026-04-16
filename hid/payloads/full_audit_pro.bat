@echo off
setlocal enabledelayedexpansion

:: Portable Security Auditor - Full Audit PRO (Pro/Enterprise Edition)
:: Gathers all security data including Local Security Policy and uploads to Pi

set "OUT=%TEMP%\audit_out"
mkdir "!OUT!" 2>nul

echo [+] Gathering System Information...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$data=@{hostname=$env:COMPUTERNAME;user=$env:USERNAME;os=(Get-WmiObject Win32_OperatingSystem).Caption}; $data | ConvertTo-Json -Depth 2 | Out-File -FilePath '!OUT!\audit_sysinfo.json' -Encoding ascii"

echo [+] Gathering Registry Policies...
powershell -NoProfile -ExecutionPolicy Bypass -Command "reg export HKLM\Software\Policies '!OUT!\t.reg' /y; if(Test-Path '!OUT!\t.reg'){Get-Content '!OUT!\t.reg' | Out-File '!OUT!\audit_hklm_policies.txt' -Encoding ascii; rm '!OUT!\t.reg'}"
powershell -NoProfile -ExecutionPolicy Bypass -Command "reg export HKCU\Software\Policies '!OUT!\t.reg' /y; if(Test-Path '!OUT!\t.reg'){Get-Content '!OUT!\t.reg' | Out-File '!OUT!\audit_hkcu_policies.txt' -Encoding ascii; rm '!OUT!\t.reg'}"

echo [+] Gathering Services and Control...
powershell -NoProfile -ExecutionPolicy Bypass -Command "reg export HKLM\SYSTEM\CurrentControlSet\Services '!OUT!\t.reg' /y; if(Test-Path '!OUT!\t.reg'){Get-Content '!OUT!\t.reg' | Out-File '!OUT!\audit_services.txt' -Encoding ascii; rm '!OUT!\t.reg'}"
powershell -NoProfile -ExecutionPolicy Bypass -Command "reg export HKLM\SYSTEM\CurrentControlSet\Control '!OUT!\t.reg' /y; if(Test-Path '!OUT!\t.reg'){Get-Content '!OUT!\t.reg' | Out-File '!OUT!\audit_control.txt' -Encoding ascii; rm '!OUT!\t.reg'}"

echo [+] Gathering Network and Defender...
netsh advfirewall firewall show rule name=all > "!OUT!\audit_firewall.txt"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-MpPreference | ConvertTo-Json -Depth 5 | Out-File -FilePath '!OUT!\audit_defender.json' -Encoding ascii"

echo [+] Gathering Hardware and Audit Policy...
pnputil /enum-drivers > "!OUT!\audit_drivers.txt"
pnputil /enum-devices > "!OUT!\audit_devices.txt"
auditpol /get /category:* > "!OUT!\audit_auditpol.txt"

echo [+] Gathering Accounts and GPO...
net user > "!OUT!\audit_net_users.txt"
gpresult /scope computer /v > "!OUT!\audit_gpresult_computer.txt"
gpresult /scope user /v > "!OUT!\audit_gpresult_user.txt"

echo [+] Gathering GPO Cache...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$gpcache='C:\ProgramData\Microsoft\Group Policy\History'; if(Test-Path $gpcache){Get-ChildItem -Recurse $gpcache | Select-Object FullName,LastWriteTime,Length | ConvertTo-Json -Depth 5 | Out-File '!OUT!\audit_gp_cache.json' -Encoding ascii}else{'{\"error\":\"GP cache path not found\"}' | Out-File '!OUT!\audit_gp_cache.json' -Encoding ascii}"

echo [+] Exporting Security Policy (SecEdit)...
secedit /export /cfg "!OUT!\audit_secpol.cfg" /quiet

echo [+] Uploading results to Pi...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$files=Get-ChildItem -Path '!OUT!\' -Filter audit_*; foreach($f in $files){Invoke-WebRequest -Uri 'http://{{SERVER_IP}}:{{UPLOAD_PORT}}' -Method POST -InFile $f.FullName -Headers @{'X-Filename'=$f.Name} -UseBasicParsing}"

echo [+] Cleaning up...
rmdir /s /q "!OUT!"

echo [+] PRO Audit Complete.
