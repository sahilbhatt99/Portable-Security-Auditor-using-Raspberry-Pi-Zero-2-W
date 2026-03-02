# Audit Parser & Report Generator

## Overview

Parses Windows security audit files and generates professional PDF reports.

## Supported Files

| File | Description | Parser |
|------|-------------|--------|
| `HKLM_Policies.reg` | HKLM Software Policies | Registry parser |
| `HKCU_Policies.reg` | HKCU Software Policies | Registry parser |
| `Services.reg` | Windows Services | Registry parser |
| `Control.reg` | System Control settings | Registry parser |
| `firewall.wfw` | Firewall configuration | Binary parser |
| `defender.json` | Windows Defender settings | JSON parser |
| `drivers.txt` | Installed drivers | Text parser |
| `devices.txt` | System devices | Text parser |

## Security Checks

### Windows Defender
- ✓ Real-time protection status
- ✓ Anti-spyware enabled
- ✓ Behavior monitoring enabled

### Drivers
- ✓ Total driver count
- ✓ Unsigned driver detection
- ✓ Security risk assessment

### Devices
- ✓ Total device count
- ✓ Problem device detection
- ✓ Driver issue identification

### Registry
- ✓ Policy key enumeration
- ✓ Service configuration analysis
- ✓ Control settings review

## Usage

### CLI Tool

```bash
# Generate report from C:\ (default)
python generate_report.py

# Specify custom paths
python generate_report.py /path/to/audit/files output_report.pdf
```

### Python API

```python
from parser import AuditParser, ReportGenerator

# Parse audit files
parser = AuditParser()
results = parser.analyze_all('C:\\')

# Generate PDF report
generator = ReportGenerator('security_report.pdf')
generator.generate(results)
```

### Flask API

```bash
# Generate report via API
curl -X POST http://raspberrypi.local/report/generate \
  -H "Content-Type: application/json" \
  -d '{"base_path": "C:\\", "output": "report.pdf"}'

# Download report
curl http://raspberrypi.local/report/download/report.pdf -O
```

## Report Contents

1. **Title Page**
   - Report date
   - Hostname
   - Risk score (0-100)

2. **Executive Summary**
   - Finding count
   - Critical issues

3. **Security Findings**
   - Numbered list of issues
   - Severity indicators

4. **Detailed Analysis**
   - Windows Defender status
   - Driver analysis
   - Device status
   - Registry summary
   - Firewall configuration

5. **Recommendations**
   - Actionable remediation steps
   - Priority-based guidance

## Risk Scoring

| Score | Level | Description |
|-------|-------|-------------|
| 0-25 | Low | Minor issues or no findings |
| 26-50 | Medium | Some security concerns |
| 51-75 | High | Multiple security issues |
| 76-100 | Critical | Severe security problems |

### Risk Factors

- Each finding: +15 points
- Disabled real-time protection: +30 points
- Disabled anti-spyware: +20 points
- Unsigned drivers: +5 points each (max 25)

## Example Output

```
SECURITY AUDIT REPORT
=====================

Report Date: 2024-01-15T10:30:00
Hostname: WORKSTATION-01
Risk Score: 45/100

EXECUTIVE SUMMARY
Analysis identified 3 security findings requiring attention.

SECURITY FINDINGS
1. Real-time protection is DISABLED
2. 2 unsigned drivers detected
3. 1 devices with problems

RECOMMENDATIONS
1. Enable Windows Defender Real-time Protection immediately
2. Review and remove unsigned drivers or obtain signed versions
3. Investigate and resolve device driver issues
```

## Dependencies

- `reportlab` - PDF generation
- Python 3.7+

## Installation

```bash
pip install reportlab
```
