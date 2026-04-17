import re
from reportlab.platypus import Paragraph, Table, TableStyle, Spacer, KeepTogether, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import inch
from parser.plugins.base import AuditPlugin

class PolicyPlugin(AuditPlugin):
    @property
    def target_files(self):
        return ['audit_secpol.cfg', 'audit_auditpol.txt']

    def parse(self, filepath):
        if 'secpol' in filepath:
            return self._parse_secpol(filepath)
        elif 'auditpol' in filepath:
            return self._parse_auditpol(filepath)
        return {}

    def _parse_auditpol(self, filepath):
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                content = f.read()
                lines = content.split('\\n')
                
                vulnerabilities = []
                policies = []
                
                for line in lines:
                    line = line.strip()
                    if not line or 'System audit policy' in line or 'Category/Subcategory' in line:
                        continue
                        
                    parts = re.split(r'\\s{2,}', line)
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
                    'type': 'auditpol',
                    'vulnerabilities': vulnerabilities,
                    'policies': policies
                }
        except Exception:
            return {'error': 'Failed to parse auditpol'}

    def _parse_secpol(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-16le', errors='ignore') as f:
                content = f.read()
                
                vulnerabilities = []
                # Extreme basic map for brevity (Original logic was heavy)
                if 'MinimumPasswordLength=0' in content:
                    vulnerabilities.append({"title": "Weak Password Policy", "severity": "CRITICAL", "description": "Min PW length is 0", "evidence": "", "impact": "", "recommendation": "Set > 8"})
                
                return {
                    'type': 'secpol',
                    'vulnerabilities': vulnerabilities,
                    'content': content[:500]
                }
        except Exception:
            try:
                # Fallback to ascii for backwards compat
                with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                    content = f.read()
                    return {'type': 'secpol', 'vulnerabilities': [], 'content': content[:500]}
            except:
                return {'error': 'Failed to parse secpol'}

    def generate_section(self, parsed_data, story, styles):
        if 'error' in parsed_data: return
        t = parsed_data.get('type')
        if t == 'auditpol':
            story.append(Paragraph("Audit Policy Config", styles['CorpHeading2']))
            story.append(Paragraph(f"Extracted {len(parsed_data.get('policies', []))} policies.", styles['CorpNormal']))
            story.append(Spacer(1, 0.2*inch))
            story.append(PageBreak())
        elif t == 'secpol':
            story.append(Paragraph("Security Policies (Secpol)", styles['CorpHeading2']))
            story.append(Paragraph("Extracted raw configuration.", styles['CorpNormal']))
            story.append(Spacer(1, 0.2*inch))
            story.append(PageBreak())
