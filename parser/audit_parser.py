"""
Audit file parser for Windows security exports.
Parses registry, firewall, defender, and device data.
"""

import json
import re
from datetime import datetime


class AuditParser:
    """Parses Windows audit output files"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'hostname': 'Unknown',
            'findings': [],
            'summary': {}
        }
    
    def parse_registry(self, filepath):
        """Parse registry export text file"""
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()
                keys = re.findall(r'\[([^\]]+)\]', content)
                values = re.findall(r'"([^"]+)"=(.+)', content)
                
                # Extract detailed entries
                entries = []
                for key in keys[:100]:  # Limit to first 100
                    entries.append({
                        'key': key,
                        'type': self._classify_registry_key(key)
                    })
                
                return {
                    'total_keys': len(keys),
                    'total_values': len(values),
                    'keys': keys[:50],
                    'detailed_entries': entries
                }
        except:
            return {'error': 'Failed to parse registry file'}
    
    def _classify_registry_key(self, key):
        """Classify registry key type"""
        if 'Policies' in key:
            return 'Security Policy'
        elif 'Services' in key:
            return 'System Service'
        elif 'Control' in key:
            return 'System Control'
        elif 'Software' in key:
            return 'Software Configuration'
        else:
            return 'General'
    
    def parse_defender(self, filepath):
        """Parse defender.json"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                findings = []
                settings = []
                
                # Check critical settings
                if not data.get('DisableRealtimeMonitoring', True):
                    findings.append('Real-time protection is DISABLED')
                
                if data.get('DisableAntiSpyware', False):
                    findings.append('Anti-spyware is DISABLED')
                
                if data.get('DisableBehaviorMonitoring', False):
                    findings.append('Behavior monitoring is DISABLED')
                
                # Extract all settings
                for key, value in data.items():
                    settings.append({
                        'setting': key,
                        'value': str(value),
                        'description': self._describe_defender_setting(key)
                    })
                
                return {
                    'realtime_enabled': not data.get('DisableRealtimeMonitoring', False),
                    'antispyware_enabled': not data.get('DisableAntiSpyware', True),
                    'behavior_monitoring': not data.get('DisableBehaviorMonitoring', True),
                    'findings': findings,
                    'all_settings': settings[:50]
                }
        except:
            return {'error': 'Failed to parse defender.json'}
    
    def _describe_defender_setting(self, setting):
        """Describe Defender setting"""
        descriptions = {
            'DisableRealtimeMonitoring': 'Controls real-time malware scanning',
            'DisableAntiSpyware': 'Controls anti-spyware protection',
            'DisableBehaviorMonitoring': 'Controls behavior-based detection',
            'DisableIOAVProtection': 'Controls downloaded file scanning',
            'DisableScriptScanning': 'Controls PowerShell script scanning',
            'SubmitSamplesConsent': 'Controls automatic sample submission',
            'MAPSReporting': 'Controls cloud-based protection level',
            'PUAProtection': 'Controls potentially unwanted application blocking'
        }
        return descriptions.get(setting, 'Windows Defender configuration setting')
    
    def parse_drivers(self, filepath):
        """Parse drivers.txt"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                drivers = re.findall(r'Published Name\s*:\s*(.+)', content)
                unsigned = re.findall(r'Signer Name\s*:\s*Not digitally signed', content)
                driver_names = re.findall(r'Driver package provider\s*:\s*(.+)', content)
                
                findings = []
                if unsigned:
                    findings.append(f'{len(unsigned)} unsigned drivers detected')
                
                # Extract detailed driver info
                detailed_drivers = []
                for i, driver in enumerate(drivers[:50]):
                    detailed_drivers.append({
                        'published_name': driver.strip(),
                        'provider': driver_names[i].strip() if i < len(driver_names) else 'Unknown',
                        'signed': i not in range(len(unsigned))
                    })
                
                return {
                    'total_drivers': len(drivers),
                    'unsigned_count': len(unsigned),
                    'findings': findings,
                    'detailed_drivers': detailed_drivers
                }
        except:
            return {'error': 'Failed to parse drivers.txt'}
    
    def parse_devices(self, filepath):
        """Parse devices.txt"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                devices = re.findall(r'Instance ID:\s*(.+)', content)
                problem_devices = re.findall(r'Problem:\s*0x([1-9A-F][0-9A-F]*)', content)
                device_names = re.findall(r'Device Description:\s*(.+)', content)
                
                findings = []
                if problem_devices:
                    findings.append(f'{len(problem_devices)} devices with problems')
                
                # Extract detailed device info
                detailed_devices = []
                for i, device in enumerate(devices[:50]):
                    detailed_devices.append({
                        'instance_id': device.strip(),
                        'description': device_names[i].strip() if i < len(device_names) else 'Unknown',
                        'has_problem': i < len(problem_devices)
                    })
                
                return {
                    'total_devices': len(devices),
                    'problem_count': len(problem_devices),
                    'findings': findings,
                    'detailed_devices': detailed_devices
                }
        except:
            return {'error': 'Failed to parse devices.txt'}
    
    def parse_firewall(self, filepath):
        """Parse firewall ascii text export"""
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()
                size = len(content)
                return {'size_bytes': size, 'status': 'exported to text'}
        except:
            return {'error': 'Failed to parse firewall text'}
    
    def analyze_all(self, base_path='C:\\'):
        """Analyze all audit files"""
        files = {
            'HKLM_Policies': f'{base_path}audit_hklm_policies.txt',
            'HKCU_Policies': f'{base_path}audit_hkcu_policies.txt',
            'Services': f'{base_path}audit_services.txt',
            'Control': f'{base_path}audit_control.txt',
            'Firewall': f'{base_path}audit_firewall.txt',
            'Defender': f'{base_path}audit_defender.json',
            'Drivers': f'{base_path}audit_drivers.txt',
            'Devices': f'{base_path}audit_devices.txt'
        }
        
        results = {}
        all_findings = []
        
        # Parse each file
        if self._file_exists(files['HKLM_Policies']):
            results['hklm_policies'] = self.parse_registry(files['HKLM_Policies'])
        
        if self._file_exists(files['HKCU_Policies']):
            results['hkcu_policies'] = self.parse_registry(files['HKCU_Policies'])
        
        if self._file_exists(files['Services']):
            results['services'] = self.parse_registry(files['Services'])
        
        if self._file_exists(files['Control']):
            results['control'] = self.parse_registry(files['Control'])
        
        if self._file_exists(files['Firewall']):
            results['firewall'] = self.parse_firewall(files['Firewall'])
        
        if self._file_exists(files['Defender']):
            defender = self.parse_defender(files['Defender'])
            results['defender'] = defender
            if 'findings' in defender:
                all_findings.extend(defender['findings'])
        
        if self._file_exists(files['Drivers']):
            drivers = self.parse_drivers(files['Drivers'])
            results['drivers'] = drivers
            if 'findings' in drivers:
                all_findings.extend(drivers['findings'])
        
        if self._file_exists(files['Devices']):
            devices = self.parse_devices(files['Devices'])
            results['devices'] = devices
            if 'findings' in devices:
                all_findings.extend(devices['findings'])
        
        self.results['summary'] = results
        self.results['findings'] = all_findings
        
        return self.results
    
    def _file_exists(self, filepath):
        """Check if file exists"""
        try:
            with open(filepath, 'r'):
                return True
        except:
            return False
    
    def get_risk_score(self):
        """Calculate risk score 0-100"""
        score = 0
        findings = self.results.get('findings', [])
        
        # Each finding adds risk
        score += len(findings) * 15
        
        # Check defender status
        defender = self.results['summary'].get('defender', {})
        if not defender.get('realtime_enabled', True):
            score += 30
        if not defender.get('antispyware_enabled', True):
            score += 20
        
        # Check unsigned drivers
        drivers = self.results['summary'].get('drivers', {})
        unsigned = drivers.get('unsigned_count', 0)
        if unsigned > 0:
            score += min(unsigned * 5, 25)
        
        return min(score, 100)
