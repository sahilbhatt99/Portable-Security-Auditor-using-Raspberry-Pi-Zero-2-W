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
                    vulnerabilities.append({
                        "title": "Task Manager Disabled",
                        "severity": "HIGH",
                        "description": "Task Manager is disabled by registry policy",
                        "evidence": "DisableTaskMgr = 1",
                        "impact": "Defense evasion / restricted system behavior",
                        "recommendation": "Enable Task Manager by setting value to 0 or deleting key"
                    })
                if re.search(r'"DisableRegistryTools"=dword:00000001', content, re.IGNORECASE):
                    vulnerabilities.append({
                        "title": "Registry Editor Disabled",
                        "severity": "HIGH",
                        "description": "Registry tools are disabled by registry policy",
                        "evidence": "DisableRegistryTools = 1",
                        "impact": "Defense evasion / restricted system behavior preventing incident response",
                        "recommendation": "Enable Registry Editor by setting value to 0 or deleting key"
                    })
                if re.search(r'"DisableCMD"=dword:00000001', content, re.IGNORECASE):
                    vulnerabilities.append({
                        "title": "Command Prompt Disabled",
                        "severity": "HIGH",
                        "description": "Command Prompt is disabled by registry policy",
                        "evidence": "DisableCMD = 1",
                        "impact": "Defense evasion / restricted system behavior preventing administrative repair",
                        "recommendation": "Enable Command Prompt by setting value to 0 or deleting key"
                    })
                
                # Check for Unquoted Service Paths
                if 'Services' in filepath:
                    blocks = content.split('\n\n')
                    for block in blocks:
                        if not block.strip(): continue
                        key_match = re.search(r'\[([^\]]+)\]', block)
                        if key_match:
                            service_key = key_match.group(1).split('\\')[-1]
                            path_match = re.search(r'"ImagePath"="([^"]+)"', block, re.IGNORECASE)
                            start_match = re.search(r'"Start"=dword:([0-9a-fA-F]+)', block, re.IGNORECASE)
                            obj_match = re.search(r'"ObjectName"="([^"]+)"', block, re.IGNORECASE)
                            
                            start_val = int(start_match.group(1), 16) if start_match else -1
                            obj_name = obj_match.group(1).strip() if obj_match else ""
                            
                            is_auto = (start_val == 2)
                            is_system = (obj_name.lower() == "localsystem")
                            
                            if path_match:
                                path = path_match.group(1)
                                if ' ' in path and not path.startswith('"') and not path.startswith('\\SystemRoot'):
                                    sev = "CRITICAL" if (is_auto and is_system) else "HIGH"
                                    vulnerabilities.append({
                                        "title": "Unquoted Service Path",
                                        "severity": sev,
                                        "description": f"Service path not quoted for service '{service_key}'",
                                        "evidence": f"ImagePath: {path}\\nAuto-start: {is_auto}\\nContext: {obj_name if obj_name else 'Unknown'}",
                                        "impact": "Privilege escalation to SYSTEM" if sev == "CRITICAL" else "Local Privilege Escalation (LPE)",
                                        "recommendation": "Add quotes to service ImagePath"
                                    })
                # Scan for anomalies
                vulnerabilities.extend(self._scan_for_registry_anomalies(content, filepath))
                
                # Extract detailed entries
                entries = []
                for key in keys:
                    entries.append({
                        'key': key,
                        'type': self._classify_registry_key(key)
                    })
                
                return {
                    'total_keys': len(keys),
                    'keys': keys,
                    'detailed_entries': entries,
                    'vulnerabilities': vulnerabilities
                }
        except Exception as e:
            return {'error': f'Failed to parse registry file: {str(e)}'}

    def _scan_for_registry_anomalies(self, content, filepath):
        anomalies = []
        # UAC Remote Restrictions
        if re.search(r'"LocalAccountTokenFilterPolicy"=dword:00000001', content, re.IGNORECASE):
            anomalies.append({
                "title": "UAC Remote Restrictions Disabled",
                "severity": "HIGH",
                "description": "LocalAccountTokenFilterPolicy is set to 1, allowing remote administrative access via local accounts.",
                "evidence": "LocalAccountTokenFilterPolicy = 1",
                "impact": "Lateral movement and remote code execution with local admin rights.",
                "recommendation": "Set LocalAccountTokenFilterPolicy to 0 or delete the key."
            })
        
        # LSA Protection
        if 'Control' in filepath:
            if not re.search(r'"RunAsPPL"=dword:00000001', content, re.IGNORECASE):
                anomalies.append({
                    "title": "LSA Protection Not Enabled",
                    "severity": "MED",
                    "description": "RunAsPPL (LSA Protection) is not strictly enforced.",
                    "evidence": "Missing or disabled RunAsPPL",
                    "impact": "Increased risk of credential dumping from LSASS memory.",
                    "recommendation": "Enable LSA Protection by setting RunAsPPL = 1 in Lsa configuration."
                })
        
        # WDigest Authentication
        if 'Control' in filepath:
            if re.search(r'"UseLogonCredential"=dword:00000001', content, re.IGNORECASE):
                anomalies.append({
                    "title": "WDigest Cleartext Credentials Enabled",
                    "severity": "HIGH",
                    "description": "WDigest authentication is configured to store cleartext passwords in memory.",
                    "evidence": "UseLogonCredential = 1",
                    "impact": "Cleartext credential dumping",
                    "recommendation": "Disable WDigest cleartext credentials by setting UseLogonCredential = 0."
                })
                
        # RDP Configuration
        if 'Control' in filepath:
            if re.search(r'"fDenyTSConnections"=dword:00000000', content, re.IGNORECASE):
                anomalies.append({
                    "title": "Remote Desktop Connections Enabled",
                    "severity": "MED",
                    "description": "Terminal Services (RDP) connections are allowed to this machine.",
                    "evidence": "fDenyTSConnections = 0",
                    "impact": "Increased attack surface for remote exploitation or brute-force.",
                    "recommendation": "Disable Remote Desktop (fDenyTSConnections = 1) if not explicitly required."
                })
                
        # AutoRun/AutoPlay
        if 'Policies' in filepath:
            if re.search(r'"NoDriveTypeAutoRun"=dword:00000000', content, re.IGNORECASE):
                anomalies.append({
                    "title": "AutoRun Protection Disabled",
                    "severity": "HIGH",
                    "description": "NoDriveTypeAutoRun is set to 0, allowing AutoRun for all drive types.",
                    "evidence": "NoDriveTypeAutoRun = 0",
                    "impact": "Execution of malicious code upon media insertion.",
                    "recommendation": "Enable AutoRun protection by setting NoDriveTypeAutoRun to 255 (0xFF)."
                })
        
        # IFEO Debugger (Sticky Keys)
        if re.search(r'\[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\(sethc\.exe|utilman\.exe|osk\.exe)\]\s*"Debugger"=', content, re.IGNORECASE) or re.search(r'\[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\.*\]\s*"Debugger"=', content, re.IGNORECASE):
            matches = re.findall(r'\[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\([^\]]+)\]\s*"Debugger"=', content, re.IGNORECASE)
            for match in matches:
                anomalies.append({
                    "title": "IFEO Debugger Injection",
                    "severity": "CRITICAL",
                    "description": f"Image File Execution Options (IFEO) debugger value set for {match}.",
                    "evidence": f"Debugger key present in IFEO for {match}",
                    "impact": "SYSTEM level code execution and persistence.",
                    "recommendation": "Remove IFEO Debugger keys."
                })
            
        return anomalies
    
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
                    'all_settings': settings
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
                    'detailed_drivers': detailed_drivers
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
                    'detailed_devices': detailed_devices
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
                all_rules = []
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
                        
                        severity = 'LOW'
                        if direction.lower() == 'in' and action.lower() == 'allow' and 'public' in profiles.lower():
                            sensitive_ports = ['445', '3389', '5985', '5986', '22', '23']
                            if localport in sensitive_ports or localport.lower() == 'any':
                                severity = 'HIGH'
                                vulnerabilities.append(f"Exposed Firewall Rule: '{name}' allows public inbound traffic on port {localport}")

                        all_rules.append({
                            'name': name,
                            'direction': direction,
                            'action': action,
                            'profiles': profiles,
                            'localport': localport,
                            'severity': severity
                        })

                # Sort rules by severity (HIGH first)
                all_rules.sort(key=lambda x: 0 if x['severity'] == 'HIGH' else 1)

                return {
                    'size_bytes': len(content), 
                    'active_rules': active_rules_count,
                    'vulnerabilities': vulnerabilities,
                    'all_rules': all_rules,
                    'status': 'parsed correctly'
                }
        except Exception as e:
            return {'error': f'Failed to parse firewall text: {str(e)}'}
    
    def parse_sysinfo(self, filepath):
        """Parse system info json"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                return {
                    'hostname': data.get('hostname', 'Unknown'),
                    'user': data.get('user', 'Unknown'),
                    'os': data.get('os', 'Unknown')
                }
        except:
            return {'error': 'Failed to parse sysinfo.json'}
            
    def parse_auditpol(self, filepath):
        """Parse auditpol text output"""
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                vulnerabilities = []
                policies = []
                
                for line in lines:
                    line = line.strip()
                    if not line or 'System audit policy' in line or 'Category/Subcategory' in line:
                        continue
                        
                    parts = re.split(r'\s{2,}', line)
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        setting = parts[1].strip()
                        policies.append({'name': name, 'setting': setting})
                        
                        if name in ['Process Creation', 'Account Logon', 'Object Access'] and 'No Auditing' in setting:
                            vulnerabilities.append({
                                'title': f"Missing Audit Policy: {name}",
                                'severity': "HIGH",
                                'description': f"{name} events are not being logged.",
                                'evidence': f"Setting: {setting}",
                                'impact': "Defense evasion and missing forensics",
                                'recommendation': f"Enable Success/Failure logging for {name}"
                            })
                
                return {
                    'vulnerabilities': vulnerabilities,
                    'policies': policies
                }
        except Exception as e:
            return {'error': f'Failed to parse auditpol: {str(e)}'}

    def parse_secpol(self, filepath):
        """Parse secedit .cfg output (UTF-16LE INI)"""
        try:
            with open(filepath, 'r', encoding='utf-16le', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                vulnerabilities = []
                settings = {}
                current_section = None
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith(';'):
                        continue
                        
                    if line.startswith('[') and line.endswith(']'):
                        current_section = line[1:-1]
                        settings[current_section] = []
                    elif current_section and '=' in line:
                        k, v = line.split('=', 1)
                        k, v = k.strip(), v.strip()
                        settings[current_section].append({'key': k, 'value': v})
                        
                        if current_section == 'System Access':
                            if k == 'MinimumPasswordAge' and v == '0':
                                vulnerabilities.append(f"Password Age bypass enabled (Min Age: {v})")
                            elif k == 'MaximumPasswordAge' and (v == '0' or v == '-1'):
                                vulnerabilities.append(f"Passwords never expire is allowed globally")
                            elif k == 'EnableGuestAccount' and v == '1':
                                vulnerabilities.append(f"Guest account is ENABLED globally")
                
                return {
                    'vulnerabilities': vulnerabilities,
                    'settings': settings
                }
        except Exception as e:
            return {'error': f'Failed to parse secpol: {str(e)}'}

    def parse_net_users(self, filepath):
        """Parse net user output"""
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()
                users = []
                for line in content.split('\n'):
                    if 'The command completed' in line or 'User accounts for' in line or '---' in line or not line.strip():
                        continue
                    parts = re.split(r'\s{2,}', line.strip())
                    for p in parts:
                        cleaned = p.strip()
                        if cleaned:
                            users.append(cleaned)
                
                return {
                    'users': users
                }
        except Exception as e:
            return {'error': f'Failed to parse net users: {str(e)}'}

    def parse_gpresult(self, filepath):
        """Parse raw gpresult output into a single string for display"""
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()
                start_idx = content.find('Applied Group Policy Objects')
                if start_idx != -1:
                    snippet = content[start_idx:start_idx+1000]
                    return {'snippet': snippet}
                return {'snippet': content[:1000]}
        except Exception as e:
            return {'error': f'Failed to parse gpresult: {str(e)}'}

    def parse_gp_cache(self, filepath):
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                data = json.load(f)
                return {'cache_count': len(data) if isinstance(data, list) else 1, 'data': data}
        except:
            return {'error': 'Failed to parse gp cache'}
            
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
            'Devices': os.path.join(base_path, 'audit_devices.txt'),
            'SysInfo': os.path.join(base_path, 'audit_sysinfo.json'),
            'AuditPol': os.path.join(base_path, 'audit_auditpol.txt'),
            'SecPol': os.path.join(base_path, 'audit_secpol.cfg'),
            'NetUsers': os.path.join(base_path, 'audit_net_users.txt'),
            'GPCache': os.path.join(base_path, 'audit_gp_cache.json'),
            'GPResultComputer': os.path.join(base_path, 'audit_gpresult_computer.txt')
        }
        
        results = {}
        all_vulnerabilities = []
        
        # Parse each file
        if self._file_exists(files['SysInfo']):
            sysinfo = self.parse_sysinfo(files['SysInfo'])
            results['sysinfo'] = sysinfo
            if 'hostname' in sysinfo and sysinfo['hostname'] != 'Unknown':
                self.results['hostname'] = sysinfo['hostname']
                
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
            
        if self._file_exists(files['AuditPol']):
            res = self.parse_auditpol(files['AuditPol'])
            results['auditpol'] = res
            all_vulnerabilities.extend(res.get('vulnerabilities', []))
            
        if self._file_exists(files['SecPol']):
            res = self.parse_secpol(files['SecPol'])
            results['secpol'] = res
            all_vulnerabilities.extend(res.get('vulnerabilities', []))
            
        if self._file_exists(files['NetUsers']):
            results['net_users'] = self.parse_net_users(files['NetUsers'])
            
        if self._file_exists(files['GPCache']):
            results['gp_cache'] = self.parse_gp_cache(files['GPCache'])
            
        if self._file_exists(files['GPResultComputer']):
            results['gpresult_computer'] = self.parse_gpresult(files['GPResultComputer'])
        
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
