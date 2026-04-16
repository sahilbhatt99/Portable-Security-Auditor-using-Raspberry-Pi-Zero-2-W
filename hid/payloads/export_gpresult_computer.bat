@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "gpresult /scope computer /v | Out-File C:\audit_gpresult_computer.txt -Encoding ascii; Invoke-WebRequest -Uri \"http://{{SERVER_IP}}:{{UPLOAD_PORT}}\" -Method POST -InFile C:\audit_gpresult_computer.txt -Headers @{\"X-Filename\"=\"audit_gpresult_computer.txt\"} -UseBasicParsing"
