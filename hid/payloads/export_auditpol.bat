@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "auditpol /get /category:* | Out-File C:\audit_auditpol.txt -Encoding ascii; Invoke-WebRequest -Uri \"http://{{SERVER_IP}}:{{UPLOAD_PORT}}\" -Method POST -InFile C:\audit_auditpol.txt -Headers @{\"X-Filename\"=\"audit_auditpol.txt\"} -UseBasicParsing"
