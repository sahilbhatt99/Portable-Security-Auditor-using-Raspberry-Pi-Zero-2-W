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
        """Parse secedit .cfg output (UTF-16LE INI) into a structured category report"""
        try:
            with open(filepath, 'r', encoding='utf-16le', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                raw_settings = {}
                current_section = None
                
                # First pass: parse the raw INI
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith(';'):
                        continue
                        
                    if line.startswith('[') and line.endswith(']'):
                        current_section = line[1:-1]
                        raw_settings[current_section] = {}
                    elif current_section and '=' in line:
                        k, v = line.split('=', 1)
                        raw_settings[current_section][k.strip()] = v.strip()

                def normalize_val(v):
                    match = re.match(r'^(\d),"?([^"]*)"?$', v)
                    if match:
                        _, rval = match.groups()
                        return rval
                    return v

                global_findings = []
                categories = []
                system_access = raw_settings.get('System Access', {})
                audit_log = raw_settings.get('Event Audit', {})
                reg_vals = raw_settings.get('Registry Values', {})
                priv_rights = raw_settings.get('Privilege Rights', {})

                # --- 1. Password Policy ---
                pw_items = []
                pw_findings = []
                pw_recs = []
                pw_risk = "LOW"
                
                min_len = int(system_access.get("MinimumPasswordLength", "0"))
                complexity = system_access.get("PasswordComplexity", "0")
                max_age = int(system_access.get("MaximumPasswordAge", "42"))
                
                pw_items.append({"key": "MinimumPasswordLength", "value": str(min_len)})
                pw_items.append({"key": "PasswordComplexity", "value": "Enabled" if complexity == "1" else "Disabled"})
                pw_items.append({"key": "MaximumPasswordAge", "value": str(max_age)})

                if min_len == 0 or min_len < 8:
                    pw_risk = "CRITICAL"
                    pw_findings.append(f"Minimum password length is {min_len}")
                    pw_recs.append("Set minimum password length to at least 8 (ideally 14+)")
                if complexity == "0":
                    pw_risk = "CRITICAL"
                    pw_findings.append("Password complexity is disabled")
                    pw_recs.append("Enable password complexity")
                if max_age == -1:
                    if pw_risk != "CRITICAL": pw_risk = "HIGH"
                    pw_findings.append("Passwords never expire")
                    pw_recs.append("Set password expiration policy (e.g. 60 or 90 days)")
                    
                categories.append({
                    "name": "Password Policy",
                    "risk": pw_risk,
                    "findings": pw_findings,
                    "recommendations": pw_recs,
                    "items": pw_items
                })
                for f in pw_findings: global_findings.append({"title": "Weak Password Policy", "severity": pw_risk, "description": f})

                # --- 2. Audit Policy ---
                audit_items = []
                audit_findings = []
                audit_recs = []
                audit_risk = "LOW"
                all_disabled = True
                
                for k, v in audit_log.items():
                    norm_v = 'Disabled' if v == '0' else 'Enabled'
                    audit_items.append({"key": k, "value": norm_v})
                    if v != '0':
                        all_disabled = False
                        
                if all_disabled and audit_items:
                    audit_risk = "CRITICAL"
                    audit_findings.append("All audit policies are disabled")
                    audit_recs.append("Enable audit logging for system, logon, and privilege events")
                    global_findings.append({"title": "No Auditing Configured", "severity": "CRITICAL", "description": "All system event audit policies are disabled."})

                categories.append({
                    "name": "Audit Policy",
                    "risk": audit_risk,
                    "findings": audit_findings,
                    "recommendations": audit_recs,
                    "items": audit_items
                })

                # --- 3. Network Security ---
                net_items = []
                net_findings = []
                net_recs = []
                net_risk = "LOW"
                
                smb_req = None
                smb_en = None
                anon_restrict = None
                
                for k, v in reg_vals.items():
                    norm = normalize_val(v)
                    lowk = k.lower()
                    if 'requiresecuritysignature' in lowk:
                        smb_req = norm
                        net_items.append({"key": "RequireSecuritySignature", "value":  "Disabled" if norm=="0" else "Enabled"})
                    elif 'enablesecuritysignature' in lowk:
                        smb_en = norm
                        net_items.append({"key": "EnableSecuritySignature", "value": "Disabled" if norm=="0" else "Enabled"})
                    elif 'restrictanonymous' in lowk and 'sam' not in lowk:
                        anon_restrict = norm
                        net_items.append({"key": "RestrictAnonymous", "value": norm})
                        
                if smb_req == "0" or smb_en == "0":
                    net_risk = "HIGH"
                    net_findings.append("SMB signing not enforced")
                    net_recs.append("Enable SMB signing to prevent relay attacks")
                if anon_restrict == "0":
                    if net_risk == "LOW": net_risk = "HIGH"
                    net_findings.append("Anonymous access allowed")
                    net_recs.append("Restrict anonymous access to named pipes and shares")
                    
                categories.append({
                    "name": "Network Security",
                    "risk": net_risk,
                    "findings": net_findings,
                    "recommendations": net_recs,
                    "items": net_items
                })
                for f in net_findings: global_findings.append({"title": "Network Security Risk", "severity": net_risk, "description": f})

                # --- 4. Credential Security ---
                cred_items = []
                cred_findings = []
                cred_recs = []
                cred_risk = "LOW"
                
                for k, v in reg_vals.items():
                    norm = normalize_val(v)
                    lowk = k.lower()
                    if 'cachedlogonscount' in lowk:
                        cred_items.append({"key": "CachedLogonsCount", "value": norm})
                        if int(norm) > 0:
                            cred_risk = "MEDIUM"
                            cred_findings.append("Cached credentials present and allowed")
                            cred_recs.append("Disable cached logons if not actively required for offline domain access")
                    if 'nolmhash' in lowk:
                        cred_items.append({"key": "NoLMHash", "value": "Enabled" if norm=="1" else "Disabled"})
                        if norm == "0":
                            cred_risk = "HIGH"
                            cred_findings.append("LM Hash creation is permitted")
                            cred_recs.append("Ensure NoLMHash is set to 1 to prevent legacy hash storage")
                            
                categories.append({
                    "name": "Credential Security",
                    "risk": cred_risk,
                    "findings": cred_findings,
                    "recommendations": cred_recs,
                    "items": cred_items
                })
                for f in cred_findings: global_findings.append({"title": "Credential Security Weakness", "severity": cred_risk, "description": f})

                # --- 5. Privileges Analysis ---
                priv_items = []
                priv_findings = []
                priv_recs = []
                priv_risk = "LOW"
                
                for right, sid_list_raw in priv_rights.items():
                    priv_items.append({"key": right, "value": sid_list_raw})
                    # If this is one of our dangerous privileges, flag it immediately
                    if right in ["SeDebugPrivilege", "SeImpersonatePrivilege"]:
                        priv_risk = "CRITICAL"
                        priv_findings.append(f"Dangerous privilege {right} assigned locally")
                        priv_recs.append(f"Remove {right} from any standard users or groups")
                    elif right in ["SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"]:
                        if priv_risk != "CRITICAL": priv_risk = "HIGH"
                        priv_findings.append(f"High-risk broad access privilege {right} assigned locally")
                        priv_recs.append(f"Restrict {right} to authorized administrative utilities")
                        
                categories.append({
                    "name": "Privilege Rights",
                    "risk": priv_risk,
                    "findings": priv_findings,
                    "recommendations": priv_recs,
                    "items": priv_items
                })
                for f in priv_findings: global_findings.append({"title": "Dangerous Privilege Right", "severity": priv_risk, "description": f})

                # Calculate Overall Risk
                overall_risk = "LOW"
                for cat in categories:
                    if cat['risk'] == 'CRITICAL':
                        overall_risk = 'CRITICAL'
                    elif cat['risk'] == 'HIGH' and overall_risk != 'CRITICAL':
                        overall_risk = 'HIGH'
                    elif cat['risk'] == 'MEDIUM' and overall_risk not in ['CRITICAL', 'HIGH']:
                        overall_risk = 'MEDIUM'

                result = {
                    "overall_risk": overall_risk,
                    "summary": f"Analyzed {len(categories)} security domains.",
                    "categories": categories,
                    "findings": global_findings,
                    "vulnerabilities": global_findings
                }
                
                return result
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
        """Parse raw gpresult output into a structured user context and GPO table"""
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()

            scope = 'Computer' if 'computer' in filepath.lower() else 'User'
            
            # 1. Parse GPOs (Flexible header matching)
            gpos = []
            # Applied GPOs
            applied_pattern = r'Applied Group Policy Objects.*?(?:\r?\n)[\s\-]+([\s\S]+?)(?:The following GPOs were not applied|Last time Group Policy was applied|The user is a part|Resultant Set|$)'
            applied_match = re.search(applied_pattern, content, re.IGNORECASE)
            if applied_match:
                block = applied_match.group(1)
                for i, line in enumerate(block.strip().splitlines()):
                    name = line.strip()
                    if name and not name.startswith('---') and name.lower() != 'n/a' and len(name) > 1:
                        gpos.append({'name': name, 'scope': scope, 'status': 'Applied', 'order': i + 1})

            # Not Applied GPOs
            not_applied_pattern = r'The following GPOs were not applied.*?(?:\r?\n)[\s\-]+([\s\S]+?)(?:\r?\n\r?\n|Last time|The user is a part|Resultant Set|$)'
            not_applied_match = re.search(not_applied_pattern, content, re.IGNORECASE)
            if not_applied_match:
                block = not_applied_match.group(1)
                for line in block.strip().splitlines():
                    name = line.strip()
                    if name and not name.startswith('---') and not name.lower().startswith('reason') and name.lower() != 'n/a' and len(name) > 1:
                        reason_match = re.search(r'Reason:\s*(.+)', block, re.IGNORECASE)
                        reason = reason_match.group(1).strip() if reason_match else 'Unknown'
                        gpos.append({'name': name, 'scope': scope, 'status': f'Not Applied ({reason})', 'order': '-'})

            # 2. Detailed RSoP Settings Extraction
            detailed_settings = []
            
            # Helper to parse Registry/Template like blocks
            # Look for: "Registry Settings", "Administrative Templates", "Security Options"
            sections = {
                'Registry Settings': r'Registry Settings[\s\-]+([\s\S]+?)(?:\r?\n\s*\r?\n\s*[A-Z][a-z]+ [A-Z][a-z]+|Resultant Set|$)',
                'Administrative Templates': r'Administrative Templates[\s\-]+([\s\S]+?)(?:\r?\n\s*\r?\n\s*[A-Z][a-z]+ [A-Z][a-z]+|Resultant Set|$)',
                'Security Options': r'Security Options[\s\-]+([\s\S]+?)(?:\r?\n\s*\r?\n\s*[A-Z][a-z]+ [A-Z][a-z]+|Resultant Set|$)'
            }

            for section_name, pattern in sections.items():
                match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
                if match:
                    block = match.group(1)
                    current_gpo = "Unknown"
                    current_entry = {}
                    
                    for line in block.splitlines():
                        line = line.strip()
                        if not line or line.startswith('---'): continue
                        
                        if line.startswith('GPO:'):
                            # Save previous if it exists
                            if 'setting' in current_entry:
                                detailed_settings.append(current_entry)
                            current_gpo = line.replace('GPO:', '').strip()
                            current_entry = {'section': section_name, 'gpo': current_gpo}
                        elif any(x in line for x in ['KeyName:', 'Setting:', 'Folder Id:', 'Policy:']):
                            # If we already have a setting in the same entry without a state, save it first
                            if 'setting' in current_entry:
                                detailed_settings.append(current_entry)
                                current_entry = {'section': section_name, 'gpo': current_gpo}
                            
                            val = line.split(':', 1)[1].strip()
                            current_entry['setting'] = val
                        elif 'ValueName:' in line:
                            current_entry['value_name'] = line.split(':', 1)[1].strip()
                        elif 'Value:' in line:
                            current_entry['value'] = line.split(':', 1)[1].strip()
                        elif 'State:' in line:
                            current_entry['state'] = line.split(':', 1)[1].strip()
                            # Entry complete
                            detailed_settings.append(current_entry)
                            current_entry = {'section': section_name, 'gpo': current_gpo}
            
            # Finalize last entry
            if current_entry and 'setting' in current_entry:
                detailed_settings.append(current_entry)

            # 3. Parse Identity Context
            user_info = {}
            os_match = re.search(r'OS Version:\s*(.+)', content)
            if os_match: user_info['os_version'] = os_match.group(1).strip()
            
            profile_match = re.search(r'Local Profile:\s*(.+)', content)
            if profile_match: user_info['profile_path'] = profile_match.group(1).strip()
            
            user_match = re.search(r'RSOP data for\s+(.+?)\s+on', content)
            if user_match: user_info['username'] = user_match.group(1).strip()

            # 4. Parse Security Groups
            groups = []
            groups_match = re.search(r'The (?:user|computer) is a part of the following security groups[\s\-]+([\s\S]+?)(?:\n\n|\r\n\r\n|The user has|Resultant Set|$)', content, re.IGNORECASE)
            if groups_match:
                for line in groups_match.group(1).strip().splitlines():
                    val = line.strip()
                    if val and not val.startswith('---') and val.lower() != 'n/a':
                        groups.append(val)

            # 5. Parse Privileges
            privileges = []
            privs_match = re.search(r'The user has the following security privileges[\s\-]+([\s\S]+?)(?:\n\n|\r\n\r\n|Resultant Set|$)', content, re.IGNORECASE)
            if privs_match:
                for line in privs_match.group(1).strip().splitlines():
                    val = line.strip()
                    if val and not val.startswith('---') and val.lower() != 'n/a':
                        privileges.append(val)

            # 6. Normalize Privileges
            priv_map = {
                "Debug programs": "SeDebugPrivilege",
                "Impersonate a client after authentication": "SeImpersonatePrivilege",
                "Back up files and directories": "SeBackupPrivilege",
                "Restore files and directories": "SeRestorePrivilege",
                "Take ownership of files or other objects": "SeTakeOwnershipPrivilege",
                "Manage auditing and security log": "SeSecurityPrivilege",
                "Load and unload device drivers": "SeLoadDriverPrivilege",
                "Bypass traverse checking": "SeChangeNotifyPrivilege",
                "Change the system time": "SeSystemtimePrivilege",
                "Shut down the system": "SeShutdownPrivilege",
                "Force shutdown from a remote system": "SeRemoteShutdownPrivilege"
            }
            normalized_privs = []
            for p in privileges:
                if p in priv_map:
                    normalized_privs.append(priv_map[p])
                else:
                    normalized_privs.append(p)

            # 7. Enhanced Risk Engine
            risk = "LOW"
            findings = []
            recommendations = []
            
            # Privilege Risks
            is_admin = any('Administrators' in g for g in groups)
            if is_admin: findings.append("User has local administrative privileges.")
                
            crit_privs = ["SeDebugPrivilege", "SeImpersonatePrivilege"]
            high_privs = ["SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"]
            
            for p in normalized_privs:
                if p in crit_privs:
                    risk = "CRITICAL"
                    findings.append(f"CRITICAL: User has {p} (High risk of SYSTEM elevation).")
                elif p in high_privs and risk != "CRITICAL":
                    risk = "HIGH"
                    findings.append(f"HIGH: User has {p} (Broad system access).")

            # GPO-based Risks
            for s in detailed_settings:
                sett = s.get('setting', '').lower()
                vn = s.get('value_name', '').lower()
                state = s.get('state', '').lower()
                val = s.get('value', '').lower()
                
                # Check setting OR value_name for UAC
                is_uac = 'uac' in sett or 'uac' in vn or 'enablelua' in sett or 'enablelua' in vn
                if is_uac and ('disabled' in state or '0' in val):
                    risk = "CRITICAL"
                    findings.append("CRITICAL: UAC/EnableLUA is strictly DISABLED via GPO.")
                
                if 'remotedesktop' in sett and 'enabled' in state:
                    if risk not in ["CRITICAL"]: risk = "HIGH"
                    findings.append("HIGH: Remote Desktop (RDP) is forced ENABLED via GPO.")
                elif 'legalnotice' in sett and 'disabled' in state:
                    findings.append("MED: Logon legal notice is disabled.")
                elif 'macros' in sett and 'enabled' in state:
                    if risk not in ["CRITICAL", "HIGH"]: risk = "HIGH"
                    findings.append("HIGH: VBA Macros are enabled via GPO (potential phishing vector).")

            return {
                'gpos': gpos, 
                'scope': scope,
                'user_info': user_info,
                'groups': sorted(list(set(groups))),
                'privileges': sorted(list(set(normalized_privs))),
                'detailed_settings': detailed_settings,
                'risk': risk,
                'findings': findings,
                'recommendations': recommendations
            }
        except Exception as e:
            return {'error': f'Failed to parse gpresult: {str(e)}'}


    def parse_gp_cache(self, filepath):
        """Extract GPO History and timestamps from the local cache metadata"""
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                data = [data]
                
            refined_data = []
            for item in data:
                refined_data.append({
                    'name': os.path.basename(item.get('FullName', 'Unknown')),
                    'last_modified': item.get('LastWriteTime', 'Unknown'),
                    'size': item.get('Length', 0),
                    'path': item.get('FullName', 'Unknown')
                })
                
            return {
                'cache_count': len(refined_data), 
                'data': refined_data,
                'findings': ["Possible lingering offline GPO configuration detected." if len(refined_data) > 3 else "Normal GPO cache state."]
            }
        except Exception as e:
            return {'error': f'Failed to parse gp cache: {str(e)}'}
            
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
            'GPResultComputer': os.path.join(base_path, 'audit_gpresult_computer.txt'),
            'GPResultUser': os.path.join(base_path, 'audit_gpresult_user.txt')
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
            
        if self._file_exists(files['GPResultUser']):
            results['gpresult_user'] = self.parse_gpresult(files['GPResultUser'])
        
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
