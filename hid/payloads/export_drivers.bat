@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "pnputil /enum-drivers | Out-File -FilePath C:\audit_drivers.txt -Encoding ascii; Invoke-WebRequest -Uri \"http://{{SERVER_IP}}:{{UPLOAD_PORT}}\" -Method POST -InFile C:\audit_drivers.txt -Headers @{\"X-Filename\"=\"audit_drivers.txt\"} -UseBasicParsing"
