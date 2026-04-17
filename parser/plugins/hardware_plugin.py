import re
from reportlab.platypus import Paragraph, Table, TableStyle, Spacer, KeepTogether, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import inch
from parser.plugins.base import AuditPlugin

class HardwarePlugin(AuditPlugin):
    @property
    def target_files(self):
        return ['audit_drivers.txt', 'audit_devices.txt']

    def parse(self, filepath):
        if 'drivers' in filepath:
            return self._parse_drivers(filepath)
        elif 'devices' in filepath:
            return self._parse_devices(filepath)
        return {}

    def _parse_drivers(self, filepath):
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
                            vulnerabilities.append({
                                "title": "Unsigned Driver",
                                "severity": "MEDIUM",
                                "description": f"Unsigned driver: {name}",
                                "evidence": f"Provider: {provider}",
                                "impact": "Execution of arbitrary malicious kernel code",
                                "recommendation": "Remove or replace unsigned drivers"
                            })
                            
                        detailed_drivers.append({
                            'published_name': name,
                            'provider': provider,
                            'signed': not unsigned,
                            'signer': signer
                        })
                
                return {
                    'type': 'drivers',
                    'total_drivers': total_drivers,
                    'unsigned_count': unsigned_count,
                    'vulnerabilities': vulnerabilities,
                    'detailed_drivers': detailed_drivers
                }
        except Exception:
            return {'error': 'Failed to parse drivers'}

    def _parse_devices(self, filepath):
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
                            vulnerabilities.append({
                                "title": "Hardware Exception",
                                "severity": "LOW",
                                "description": f"Problematic device '{desc}'",
                                "evidence": f"Code {problem}",
                                "impact": "Physical hardware access vectors failing",
                                "recommendation": "Investigate device manager"
                            })
                            
                        detailed_devices.append({
                            'instance_id': instance_id,
                            'description': desc,
                            'has_problem': has_problem,
                            'status': status,
                            'problem_code': problem
                        })
                
                return {
                    'type': 'devices',
                    'total_devices': total_devices,
                    'problem_count': problem_count,
                    'vulnerabilities': vulnerabilities,
                    'detailed_devices': detailed_devices
                }
        except Exception:
            return {'error': 'Failed to parse devices'}


    def generate_section(self, parsed_data, story, styles):
        if 'error' in parsed_data: return
        t = parsed_data.get('type')
        
        if t == 'drivers':
            story.append(Paragraph(f"Installed Drivers ({parsed_data.get('total_drivers', 0)} total, {parsed_data.get('unsigned_count', 0)} unsigned)", styles['CorpHeading2']))
            all_drvs = parsed_data.get('detailed_drivers', [])
            if all_drvs:
                data = [['Published Name', 'Provider', 'Signed', 'Signer']]
                count = 0
                for d in all_drvs:
                    if count >= 30: break
                    row_style = styles['DangerText'] if not d.get('signed') else styles['CorpNormal']
                    data.append([
                        Paragraph(d.get('published_name', '')[:40], styles['CorpNormal']),
                        Paragraph(d.get('provider', '')[:30], styles['CorpNormal']),
                        Paragraph("Yes" if d.get('signed') else "No", row_style),
                        Paragraph(d.get('signer', '')[:30], row_style)
                    ])
                    count += 1
                table = Table(data, colWidths=[2.5*inch, 2*inch, 0.8*inch, 1.7*inch], repeatRows=1)
            else:
                table = Paragraph("No Drivers extracted", styles['CorpNormal'])
            story.append(table)
            
        elif t == 'devices':
            story.append(Paragraph(f"Hardware Devices ({parsed_data.get('total_devices', 0)} total, {parsed_data.get('problem_count', 0)} with problems)", styles['CorpHeading2']))
            all_devs = parsed_data.get('detailed_devices', [])
            if all_devs:
                data = [['Description', 'Status', 'Instance ID', 'Problem Code']]
                count = 0
                for d in all_devs:
                    if count >= 30: break
                    row_style = styles['DangerText'] if d.get('has_problem') else styles['CorpNormal']
                    data.append([
                        Paragraph(d.get('description', '')[:50], styles['CorpNormal']),
                        Paragraph(d.get('status', 'Unknown'), row_style),
                        Paragraph(d.get('instance_id', '')[:30], styles['CorpNormal']),
                        Paragraph(d.get('problem_code') or 'None', row_style)
                    ])
                    count += 1
                table = Table(data, colWidths=[2.5*inch, 1.2*inch, 2.5*inch, 0.8*inch], repeatRows=1)
            else:
                table = Paragraph("No Devices extracted", styles['CorpNormal'])
            story.append(table)
            
        story.append(Spacer(1, 0.3*inch))
        story.append(PageBreak())
