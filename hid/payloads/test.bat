@echo off
echo Security Audit - {{TIMESTAMP}} > "%TEMP%\test_audit.txt"
echo Host: {{HOST_ID}} >> "%TEMP%\test_audit.txt"
notepad "%TEMP%\test_audit.txt"
