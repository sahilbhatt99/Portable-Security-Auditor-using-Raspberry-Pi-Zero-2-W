#!/usr/bin/env python3
"""
Test upload server connectivity from Windows
"""

import sys

# Test payload that creates a small file and uploads it
TEST_PAYLOAD = """
$ip = "172.16.0.1"
$testFile = "C:\\test_upload.txt"
"Test upload from Windows" | Out-File -FilePath $testFile -Encoding ASCII
try {
    Invoke-WebRequest -Uri "http://$ip:8000" -Method POST -InFile $testFile -Headers @{"X-Filename"="test_upload.txt"} -UseBasicParsing
    Write-Host "Upload successful"
} catch {
    Write-Host "Upload failed: $_"
}
Remove-Item $testFile -ErrorAction SilentlyContinue
"""

print("Test PowerShell command to verify upload:")
print("=" * 60)
print(TEST_PAYLOAD)
print("=" * 60)
print("\nRun this in PowerShell on Windows to test upload server")
print("File should appear in uploads/ directory on Pi")
