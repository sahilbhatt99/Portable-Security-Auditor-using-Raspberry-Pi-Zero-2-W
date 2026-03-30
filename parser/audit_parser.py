"""
Audit file parser for Windows security exports.
Parses registry, firewall, defender, and device data.
"""

import json
import re
import os
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
                
                vulnerabilities = []
                keys = re.findall(r'\[([^\]]+)\]', content)
                
                # Check for critical disabled policies
                if re.search(r'"DisableTaskMgr"=dword:00000001', content, re.IGNORECASE):
                    vulnerabilities.append("Task Manager is disabled by policy (Potential malware activity)")
                if re.search(r'"DisableRegistryTools"=dword:00000001', content, re.IGNORECASE):
                    vulnerabilities.append("Registry Editor is disabled by policy (Potential malware activity)")
                if re.search(r'"DisableCMD"=dword:00000001', content, re.IGNORECASE):
                    vulnerabilities.append("Command Prompt is disabled by policy (Potential malware activity)")
                
                # Check for Unquoted Service Paths
                if 'Services' in filepath:
                    blocks = content.split('\n\n')
                    for block in blocks:
                        if not block.strip(): continue
                        key_match = re.search(r'\[([^\]]+)\]', block)
                        if key_match:
                            service_key = key_match.group(1).split('\\')[-1]
                            path_match = re.search(r'"ImagePath"="([^"]+)"', block)
                            if path_match:
                                path = path_match.group(1)
                                if ' ' in path and not path.startswith('"') and not path.startswith('\\SystemRoot'):
                                    vulnerabilities.append(f"Unquoted Service Path in '{service_key}': {path}")
                
                # Extract detailed entries
                entries = []
                for key in keys[:100]:  # Limit to first 100
                    entries.append({
                        'key': key,
                        'type': self._classify_registry_key(key)
                    })
                
                return {
                    'total_keys': len(keys),
                    'keys': keys[:50],
                    'detailed_entries': entries,
                    'vulnerabilities': vulnerabilities
                }
        except Exception as e:
            return {'error': f'Failed to parse registry file: {str(e)}'}
    
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
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()
                blocks = content.split('\n\n')
                
                vulnerabilities = []
                detailed_drivers = []
                unsigned_count = 0
                total_drivers = 0
                
                for block in blocks:
                    if not block.strip() or 'Microsoft PnP Utility' in block: continue
                    total_drivers += 1
                    
                    name_m = re.search(r'Published Name\s*:\s*(.+)', block)
                    if not name_m:
                        name_m = re.search(r'Original Name\s*:\s*(.+)', block)
                        
                    provider_m = re.search(r'Provider Name\s*:\s*(.+)', block)
                    signer_m = re.search(r'Signer Name\s*:\s*(.+)', block)
                    
                    if name_m:
                        name = name_m.group(1).strip()
                        provider = provider_m.group(1).strip() if provider_m else 'Unknown'
                        signer = signer_m.group(1).strip() if signer_m else 'Unknown'
                        
                        unsigned = ('Not digitally signed' in signer) or (signer == 'Unknown')
                        if unsigned:
                            unsigned_count += 1
                            vulnerabilities.append(f"Unsigned driver: {name} (Provider: {provider})")
                            
                        detailed_drivers.append({
                            'published_name': name,
                            'provider': provider,
                            'signed': not unsigned,
                            'signer': signer
                        })
                
                return {
                    'total_drivers': total_drivers,
                    'unsigned_count': unsigned_count,
                    'vulnerabilities': vulnerabilities,
                    'detailed_drivers': detailed_drivers[:50]
                }
        except Exception as e:
            return {'error': f'Failed to parse drivers.txt: {str(e)}'}
    
    def parse_devices(self, filepath):
        """Parse devices.txt"""
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()
                blocks = content.split('\n\n')
                
                vulnerabilities = []
                detailed_devices = []
                problem_count = 0
                total_devices = 0
                
                for block in blocks:
                    if not block.strip() or 'Microsoft PnP Utility' in block: continue
                    total_devices += 1
                    
                    instance_id_m = re.search(r'Instance ID:\s*(.+)', block)
                    desc_m = re.search(r'Device Description:\s*(.+)', block)
                    status_m = re.search(r'Status:\s*(.+)', block)
                    problem_m = re.search(r'Problem:\s*(.+)', block)
                    
                    if instance_id_m:
                        instance_id = instance_id_m.group(1).strip()
                        desc = desc_m.group(1).strip() if desc_m else 'Unknown'
                        status = status_m.group(1).strip() if status_m else 'Unknown'
                        problem = problem_m.group(1).strip() if problem_m else None
                        
                        has_problem = problem is not None and problem != '0'
                        if has_problem:
                            problem_count += 1
                            vulnerabilities.append(f"Problematic device '{desc}': Code {problem}")
                            
                        detailed_devices.append({
                            'instance_id': instance_id,
                            'description': desc,
                            'has_problem': has_problem,
                            'status': status,
                            'problem_code': problem
                        })
                
                return {
                    'total_devices': total_devices,
                    'problem_count': problem_count,
                    'vulnerabilities': vulnerabilities,
                    'detailed_devices': detailed_devices[:50]
                }
        except Exception as e:
            return {'error': f'Failed to parse devices.txt: {str(e)}'}
    
    def parse_firewall(self, filepath):
        """Parse firewall ascii text export"""
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()
                blocks = re.split(r'Rule Name:\s*', content)
                
                vulnerabilities = []
                active_rules_count = 0
                
                for block in blocks[1:]:
                    rule_text = 'Rule Name: ' + block
                    name_m = re.search(r'Rule Name:\s*(.+)', rule_text)
                    enabled_m = re.search(r'Enabled:\s*(.+)', rule_text)
                    
                    if name_m and enabled_m and enabled_m.group(1).strip().lower() == 'yes':
                        active_rules_count += 1
                        
                        direction_m = re.search(r'Direction:\s*(.+)', rule_text)
                        profiles_m = re.search(r'Profiles:\s*(.+)', rule_text)
                        action_m = re.search(r'Action:\s*(.+)', rule_text)
                        localport_m = re.search(r'LocalPort:\s*(.+)', rule_text)
                        
                        name = name_m.group(1).strip()
                        direction = direction_m.group(1).strip() if direction_m else ''
                        profiles = profiles_m.group(1).strip() if profiles_m else ''
                        action = action_m.group(1).strip() if action_m else ''
                        localport = localport_m.group(1).strip() if localport_m else ''
                        
                        if direction.lower() == 'in' and action.lower() == 'allow' and 'public' in profiles.lower():
                            sensitive_ports = ['445', '3389', '5985', '5986', '22', '23']
                            if localport in sensitive_ports or localport.lower() == 'any':
                                vulnerabilities.append(f"Exposed Firewall Rule: '{name}' allows public inbound traffic on port {localport}")

                return {
                    'size_bytes': len(content), 
                    'active_rules': active_rules_count,
                    'vulnerabilities': vulnerabilities,
                    'status': 'parsed correctly'
                }
        except Exception as e:
            return {'error': f'Failed to parse firewall text: {str(e)}'}
    
    def analyze_all(self, base_path='C:\\'):
        """Analyze all audit files"""
        
        # Determine if base_path is empty or missing files, try fallback
        if not self._file_exists(os.path.join(base_path, 'audit_hklm_policies.txt')):
            # Check for Full_Audit in CWD
            if os.path.exists('Full_Audit') and os.path.isdir('Full_Audit'):
                base_path = 'Full_Audit/'
            # Check for Full_Audit in Parent Dir
            elif os.path.exists('../Full_Audit') and os.path.isdir('../Full_Audit'):
                base_path = '../Full_Audit/'
                
        files = {
            'HKLM_Policies': os.path.join(base_path, 'audit_hklm_policies.txt'),
            'HKCU_Policies': os.path.join(base_path, 'audit_hkcu_policies.txt'),
            'Services': os.path.join(base_path, 'audit_services.txt'),
            'Control': os.path.join(base_path, 'audit_control.txt'),
            'Firewall': os.path.join(base_path, 'audit_firewall.txt'),
            'Defender': os.path.join(base_path, 'audit_defender.json'),
            'Drivers': os.path.join(base_path, 'audit_drivers.txt'),
            'Devices': os.path.join(base_path, 'audit_devices.txt')
        }
        
        results = {}
        all_vulnerabilities = []
        
        # Parse each file
        if self._file_exists(files['HKLM_Policies']):
            results['hklm_policies'] = self.parse_registry(files['HKLM_Policies'])
            all_vulnerabilities.extend(results['hklm_policies'].get('vulnerabilities', []))
        
        if self._file_exists(files['HKCU_Policies']):
            results['hkcu_policies'] = self.parse_registry(files['HKCU_Policies'])
            all_vulnerabilities.extend(results['hkcu_policies'].get('vulnerabilities', []))
        
        if self._file_exists(files['Services']):
            results['services'] = self.parse_registry(files['Services'])
            all_vulnerabilities.extend(results['services'].get('vulnerabilities', []))
        
        if self._file_exists(files['Control']):
            results['control'] = self.parse_registry(files['Control'])
            all_vulnerabilities.extend(results['control'].get('vulnerabilities', []))
        
        if self._file_exists(files['Firewall']):
            firewall = self.parse_firewall(files['Firewall'])
            results['firewall'] = firewall
            all_vulnerabilities.extend(firewall.get('vulnerabilities', []))
        
        if self._file_exists(files['Defender']):
            defender = self.parse_defender(files['Defender'])
            results['defender'] = defender
            if 'findings' in defender:
                all_vulnerabilities.extend(defender['findings'])
        
        if self._file_exists(files['Drivers']):
            drivers = self.parse_drivers(files['Drivers'])
            results['drivers'] = drivers
            all_vulnerabilities.extend(drivers.get('vulnerabilities', []))
        
        if self._file_exists(files['Devices']):
            devices = self.parse_devices(files['Devices'])
            results['devices'] = devices
            all_vulnerabilities.extend(devices.get('vulnerabilities', []))
        
        self.results['summary'] = results
        self.results['findings'] = all_vulnerabilities  # Update findings with the comprehensive array
        
        return self.results
    
    def _file_exists(self, filepath):
        """Check if file exists"""
        return os.path.exists(filepath)
    
    def get_risk_score(self):
        """Calculate risk score 0-100"""
        score = 0
        findings = self.results.get('findings', [])
        
        # Each finding adds risk
        score += len(findings) * 15
        
        return min(score, 100)
