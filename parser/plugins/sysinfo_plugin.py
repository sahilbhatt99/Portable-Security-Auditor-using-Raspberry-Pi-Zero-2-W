import json
from reportlab.platypus import Paragraph, Spacer, PageBreak
from parser.plugins.base import AuditPlugin

class SysinfoPlugin(AuditPlugin):
    @property
    def target_files(self): return ['audit_sysinfo.json']
    def parse(self, filepath):
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                return {'hostname': data.get('hostname'), 'user': data.get('user'), 'os': data.get('os')}
        except: return {}
    def generate_section(self, parsed_data, story, styles):
        return # Sysinfo is injected manually into Cover Page
