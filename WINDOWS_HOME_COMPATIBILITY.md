# Windows Home Compatibility Analysis

## Commands Analysis

### ✅ Works on Windows Home (9 commands)

1. **reg export "HKLM\Software\Policies" C:\HKLM_Policies.reg**
   - Status: ✅ Works
   - Payload: `export_policies`

2. **reg export "HKCU\Software\Policies" C:\HKCU_Policies.reg**
   - Status: ✅ Works
   - Payload: `export_user_policies`

3. **reg export "HKLM\SYSTEM\CurrentControlSet\Services" C:\Services.reg**
   - Status: ✅ Works
   - Payload: `export_services`

4. **reg export "HKLM\SYSTEM\CurrentControlSet\Control" C:\Control.reg**
   - Status: ✅ Works
   - Payload: `export_control`

5. **netsh advfirewall export C:\firewall.wfw**
   - Status: ✅ Works
   - Payload: `export_firewall`

6. **Get-MpPreference | ConvertTo-Json -Depth 5 > C:\defender.json**
   - Status: ✅ Works
   - Payload: `export_defender`

7. **pnputil /enum-drivers > C:\drivers.txt**
   - Status: ✅ Works
   - Payload: `export_drivers`

8. **pnputil /enum-devices > C:\devices.txt**
   - Status: ✅ Works
   - Payload: `export_devices`

9. **Combined Full Audit**
   - Status: ✅ Works
   - Payload: `full_audit`

### ❌ Does NOT Work on Windows Home (2 commands)

1. **reg save HKLM C:\HKLM.hiv**
   - Status: ❌ Requires Admin + Pro/Enterprise
   - Reason: `reg save` requires elevated privileges and is restricted on Home
   - Alternative: Use `reg export` for specific keys instead

2. **reg save HKCU C:\HKCU.hiv**
   - Status: ❌ Requires Admin + Pro/Enterprise
   - Reason: `reg save` requires elevated privileges and is restricted on Home
   - Alternative: Use `reg export` for specific keys instead

## Summary

**9 out of 11 commands work on Windows Home (82% compatibility)**

## Available Payloads

| Payload Name | Description | Output File |
|--------------|-------------|-------------|
| `export_policies` | Export HKLM Policies | C:\HKLM_Policies.reg |
| `export_user_policies` | Export HKCU Policies | C:\HKCU_Policies.reg |
| `export_services` | Export Services | C:\Services.reg |
| `export_control` | Export Control | C:\Control.reg |
| `export_firewall` | Export Firewall Config | C:\firewall.wfw |
| `export_defender` | Export Defender Settings | C:\defender.json |
| `export_drivers` | Export Driver List | C:\drivers.txt |
| `export_devices` | Export Device List | C:\devices.txt |
| `full_audit` | Run All Exports | Multiple files |

## Usage

```python
from hid import HIDController

controller = HIDController()
controller.enable_hid()

# Execute individual payload
controller.execute_payload('export_firewall')

# Execute full audit
controller.execute_payload('full_audit')
```

## Notes

- All commands write to C:\ root (requires admin on some systems)
- `reg save` creates binary hive files (not supported on Home)
- `reg export` creates text .reg files (works on all editions)
- Full audit takes ~10-15 seconds to complete
- Files can be retrieved via USB mass storage or network
