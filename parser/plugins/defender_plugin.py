import json
from reportlab.platypus import Paragraph, Table, TableStyle, Spacer, KeepTogether, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import inch
from parser.plugins.base import AuditPlugin

class DefenderPlugin(AuditPlugin):
    @property
    def target_files(self):
        return ['audit_defender.json']

    def parse(self, filepath):
        """Parse defender.json"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                findings = []
                settings = []
                
                if not data.get('DisableRealtimeMonitoring', True):
                    findings.append('Real-time protection is DISABLED')
                
                if data.get('DisableAntiSpyware', False):
                    findings.append('Anti-spyware is DISABLED')
                
                if data.get('DisableBehaviorMonitoring', False):
                    findings.append('Behavior monitoring is DISABLED')
                
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

    def generate_section(self, parsed_data, story, styles):
        if 'error' in parsed_data:
            return
            
        story.append(Paragraph("Windows Defender Overview", styles['CorpHeading2']))
        
        status_data = [
            ['Component', 'Status'],
            ['Real-time Scanning', Paragraph('Enabled', styles['CorpNormal']) if parsed_data.get('realtime_enabled') else Paragraph('Disabled', styles['DangerText'])],
            ['Anti-Spyware', 'Enabled' if parsed_data.get('antispyware_enabled') else 'Disabled'],
            ['Behavior Monitoring', 'Enabled' if parsed_data.get('behavior_monitoring') else 'Disabled']
        ]
        
        status_table = Table(status_data, colWidths=[2.5*inch, 1.5*inch])
        status_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e6e6e6')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ('TEXTCOLOR', (1, 1), (1, -1), colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(status_table)
        story.append(Spacer(1, 0.2*inch))
        
        all_settings = parsed_data.get('all_settings', [])
        if all_settings:
            detailed_data = [['Configuration Setting', 'Value', 'Description']]
            for setting in all_settings:
                detailed_data.append([
                    Paragraph(setting.get('setting', ''), styles['CorpNormal']),
                    Paragraph(setting.get('value', ''), styles['CorpNormal']),
                    Paragraph(setting.get('description', ''), styles['CorpEducational'])
                ])
                
            det_table = Table(detailed_data, colWidths=[2.2*inch, 1.0*inch, 3.8*inch], repeatRows=1)
            det_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f497d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(KeepTogether([det_table, Spacer(1, 0.3*inch)]))
            
        story.append(PageBreak())
