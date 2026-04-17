import re
from reportlab.platypus import Paragraph, Table, TableStyle, Spacer, KeepTogether, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import inch
from parser.plugins.base import AuditPlugin

class FirewallPlugin(AuditPlugin):
    @property
    def target_files(self):
        return ['audit_firewall.txt']

    def parse(self, filepath):
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
                                vulnerabilities.append({
                                    "title": "Exposed Firewall Rule",
                                    "severity": "HIGH",
                                    "description": f"Rule allows public inbound traffic on port {localport}",
                                    "evidence": f"Rule: '{name}'",
                                    "impact": "Remote Exploitation/Network Breach",
                                    "recommendation": "Disable rule or restrict profiles strictly to Domain/Private"
                                })

                        all_rules.append({
                            'name': name,
                            'direction': direction,
                            'action': action,
                            'profiles': profiles,
                            'localport': localport,
                            'severity': severity
                        })

                all_rules.sort(key=lambda x: 0 if x['severity'] == 'HIGH' else 1)

                return {
                    'active_rules': active_rules_count,
                    'vulnerabilities': vulnerabilities,
                    'all_rules': all_rules,
                    'status': 'parsed correctly'
                }
        except Exception as e:
            return {'error': f'Failed to parse firewall text: {str(e)}'}

    def generate_section(self, parsed_data, story, styles):
        if 'error' in parsed_data:
            return
            
        story.append(Paragraph(f"Windows Defender Firewall (Active Rules: {parsed_data.get('active_rules', 0)})", styles['CorpHeading2']))
        
        all_rules = parsed_data.get('all_rules', [])
        if all_rules:
            data = [['Rule Name', 'Direction', 'Action', 'Profiles', 'Local Port']]
            count = 0
            
            for rule in all_rules:
                if count >= 30:
                    break
                row_style = styles['DangerText'] if rule.get('severity') == 'HIGH' else styles['CorpNormal']
                data.append([
                    Paragraph(rule.get('name', '')[:40], styles['CorpNormal']),
                    Paragraph(rule.get('direction', ''), styles['CorpNormal']),
                    Paragraph(rule.get('action', ''), row_style),
                    Paragraph(rule.get('profiles', ''), styles['CorpNormal']),
                    Paragraph(rule.get('localport', ''), row_style),
                ])
                count += 1
                
            if len(all_rules) > 30:
                data.append([Paragraph(f"... plus {len(all_rules)-30} additional rules", styles['CorpEducational']), "", "", "", ""])

            table = Table(data, colWidths=[2.5*inch, 0.8*inch, 0.8*inch, 1.5*inch, 1.4*inch], repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f497d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            import reportlab.platypus
            story.append(reportlab.platypus.KeepTogether([table, Spacer(1, 0.3*inch)]))
            
        story.append(PageBreak())
