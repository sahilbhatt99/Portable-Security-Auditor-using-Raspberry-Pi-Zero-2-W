import re
from reportlab.platypus import Paragraph, Table, TableStyle, Spacer, KeepTogether, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import inch
from parser.plugins.base import AuditPlugin

class RegistryPlugin(AuditPlugin):
    @property
    def target_files(self):
        return ['audit_hklm_policies.txt', 'audit_hkcu_policies.txt', 'audit_services.txt', 'audit_control.txt']

    def parse(self, filepath):
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()
                
                vulnerabilities = []
                keys = re.findall(r'\[([^\]]+)\]', content)
                
                if re.search(r'"DisableTaskMgr"=dword:00000001', content, re.IGNORECASE):
                    vulnerabilities.append({
                        "title": "Task Manager Disabled", "severity": "HIGH",
                        "description": "Task Manager is disabled by registry policy", "evidence": "DisableTaskMgr = 1",
                        "impact": "Defense evasion / restricted system behavior", "recommendation": "Enable Task Manager by setting value to 0 or deleting key"
                    })
                if re.search(r'"DisableRegistryTools"=dword:00000001', content, re.IGNORECASE):
                    vulnerabilities.append({
                        "title": "Registry Editor Disabled", "severity": "HIGH",
                        "description": "Registry tools are disabled", "evidence": "DisableRegistryTools = 1",
                        "impact": "Defense evasion", "recommendation": "Set value to 0"
                    })
                if re.search(r'"DisableCMD"=dword:00000001', content, re.IGNORECASE):
                    vulnerabilities.append({
                        "title": "Command Prompt Disabled", "severity": "HIGH",
                        "description": "CMD is disabled by registry policy", "evidence": "DisableCMD = 1",
                        "impact": "Defense evasion", "recommendation": "Set value to 0"
                    })
                
                if 'Services' in filepath:
                    blocks = content.split('\\n\\n')
                    for block in blocks:
                        if not block.strip(): continue
                        key_match = re.search(r'\[([^\]]+)\]', block)
                        if key_match:
                            service_key = key_match.group(1).split('\\\\')[-1]
                            path_match = re.search(r'"ImagePath"="([^"]+)"', block, re.IGNORECASE)
                            start_match = re.search(r'"Start"=dword:([0-9a-fA-F]+)', block, re.IGNORECASE)
                            obj_match = re.search(r'"ObjectName"="([^"]+)"', block, re.IGNORECASE)
                            
                            start_val = int(start_match.group(1), 16) if start_match else -1
                            obj_name = obj_match.group(1).strip() if obj_match else ""
                            
                            is_auto = (start_val == 2)
                            is_system = (obj_name.lower() == "localsystem")
                            
                            if path_match:
                                path = path_match.group(1)
                                if ' ' in path and not path.startswith('"') and not path.startswith('\\\\SystemRoot'):
                                    sev = "CRITICAL" if (is_auto and is_system) else "HIGH"
                                    vulnerabilities.append({
                                        "title": "Unquoted Service Path", "severity": sev,
                                        "description": f"Service path not quoted for service '{service_key}'",
                                        "evidence": f"ImagePath: {path}\\nAuto-start: {is_auto}\\nContext: {obj_name if obj_name else 'Unknown'}",
                                        "impact": "Privilege escalation to SYSTEM" if sev == "CRITICAL" else "Local Privilege Escalation (LPE)",
                                        "recommendation": "Add quotes to service ImagePath"
                                    })
                vulnerabilities.extend(self._scan_for_registry_anomalies(content, filepath))
                
                return {'vulnerabilities': vulnerabilities, 'keys_count': len(keys), 'type': 'registry', 'filepath': filepath}
        except Exception:
            return {'error': 'Failed to parse registry'}

    def _scan_for_registry_anomalies(self, content, filepath):
        anomalies = []
        if re.search(r'"LocalAccountTokenFilterPolicy"=dword:00000001', content, re.IGNORECASE):
            anomalies.append({
                "title": "UAC Remote Restrictions Disabled", "severity": "HIGH",
                "description": "LocalAccountTokenFilterPolicy is set to 1.", "evidence": "LocalAccountTokenFilterPolicy = 1",
                "impact": "Lateral movement and remote code execution.", "recommendation": "Set to 0."
            })
        if 'Control' in filepath:
            if not re.search(r'"RunAsPPL"=dword:00000001', content, re.IGNORECASE):
                anomalies.append({
                    "title": "LSA Protection Not Enabled", "severity": "MED",
                    "description": "RunAsPPL is not enforced.", "evidence": "Missing RunAsPPL",
                    "impact": "Increased risk of credential dumping.", "recommendation": "Set RunAsPPL = 1"
                })
            if re.search(r'"UseLogonCredential"=dword:00000001', content, re.IGNORECASE):
                anomalies.append({
                    "title": "WDigest Cleartext Credentials Enabled", "severity": "HIGH",
                    "description": "WDigest logic active.", "evidence": "UseLogonCredential = 1",
                    "impact": "Cleartext dumping", "recommendation": "Set to 0."
                })
        if 'Policies' in filepath:
            if re.search(r'"NoDriveTypeAutoRun"=dword:00000000', content, re.IGNORECASE):
                anomalies.append({"title": "AutoRun Protection Disabled", "severity": "HIGH", "description": "NoDriveTypeAutoRun is 0.", "evidence": "", "impact": "", "recommendation": "Set to 255"})
        matches = re.findall(r'\[HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\([^\]]+)\]\\s*"Debugger"=', content, re.IGNORECASE)
        for match in matches:
            anomalies.append({"title": "IFEO Debugger Injection", "severity": "CRITICAL", "description": f"IFEO logic for {match}", "evidence": "", "impact": "", "recommendation": "Remove key"})
        return anomalies

    def generate_section(self, parsed_data, story, styles):
        if 'error' in parsed_data: return
        t = parsed_data.get('filepath', 'Unknown')
        story.append(Paragraph(f"Registry Extract: {t}", styles['CorpHeading2']))
        story.append(Paragraph(f"Keys automatically parsed: {parsed_data.get('keys_count', 0)}", styles['CorpNormal']))
        story.append(Spacer(1, 0.2*inch))
        story.append(PageBreak())
