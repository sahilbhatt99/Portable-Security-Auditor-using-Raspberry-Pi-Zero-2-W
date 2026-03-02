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
        """Parse .reg file"""
        try:
            with open(filepath, 'r', encoding='utf-16-le') as f:
                content = f.read()
                keys = re.findall(r'\[([^\]]+)\]', content)
                return {'total_keys': len(keys), 'keys': keys[:50]}
        except:
            return {'error': 'Failed to parse registry file'}
    
    def parse_defender(self, filepath):
        """Parse defender.json"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                findings = []
                
                # Check critical settings
                if not data.get('DisableRealtimeMonitoring', True):
                    findings.append('Real-time protection is DISABLED')
                
                if data.get('DisableAntiSpyware', False):
                    findings.append('Anti-spyware is DISABLED')
                
                if data.get('DisableBehaviorMonitoring', False):
                    findings.append('Behavior monitoring is DISABLED')
                
                return {
                    'realtime_enabled': not data.get('DisableRealtimeMonitoring', False),
                    'antispyware_enabled': not data.get('DisableAntiSpyware', True),
                    'behavior_monitoring': not data.get('DisableBehaviorMonitoring', True),
                    'findings': findings
                }
        except:
            return {'error': 'Failed to parse defender.json'}
    
    def parse_drivers(self, filepath):
        """Parse drivers.txt"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                drivers = re.findall(r'Published Name\s*:\s*(.+)', content)
                unsigned = re.findall(r'Signer Name\s*:\s*Not digitally signed', content)
                
                findings = []
                if unsigned:
                    findings.append(f'{len(unsigned)} unsigned drivers detected')
                
                return {
                    'total_drivers': len(drivers),
                    'unsigned_count': len(unsigned),
                    'findings': findings
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
                
                findings = []
                if problem_devices:
                    findings.append(f'{len(problem_devices)} devices with problems')
                
                return {
                    'total_devices': len(devices),
                    'problem_count': len(problem_devices),
                    'findings': findings
                }
        except:
            return {'error': 'Failed to parse devices.txt'}
    
    def parse_firewall(self, filepath):
        """Parse firewall.wfw (binary format - basic check only)"""
        try:
            with open(filepath, 'rb') as f:
                size = len(f.read())
                return {'size_bytes': size, 'status': 'exported'}
        except:
            return {'error': 'Failed to parse firewall.wfw'}
    
    def analyze_all(self, base_path='C:\\'):
        """Analyze all audit files"""
        files = {
            'HKLM_Policies': f'{base_path}HKLM_Policies.reg',
            'HKCU_Policies': f'{base_path}HKCU_Policies.reg',
            'Services': f'{base_path}Services.reg',
            'Control': f'{base_path}Control.reg',
            'Firewall': f'{base_path}firewall.wfw',
            'Defender': f'{base_path}defender.json',
            'Drivers': f'{base_path}drivers.txt',
            'Devices': f'{base_path}devices.txt'
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
