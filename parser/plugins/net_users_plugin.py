import re
from reportlab.platypus import Paragraph, Spacer, PageBreak
from parser.plugins.base import AuditPlugin

class NetUsersPlugin(AuditPlugin):
    @property
    def target_files(self): return ['audit_net_users.txt']
    def parse(self, filepath):
        try:
            with open(filepath, 'r', encoding='ascii', errors='ignore') as f:
                c = f.read()
                users = []
                for line in c.split('\n'):
                    if 'The command completed' in line or 'User accounts for' in line or '---' in line or not line.strip(): continue
                    parts = re.split(r'\s{2,}', line.strip())
                    for p in parts:
                        if p.strip(): users.append(p.strip())
                return {'users': users}
        except: return {}
    def generate_section(self, parsed_data, story, styles):
        if 'users' in parsed_data:
            story.append(Paragraph("Local Accounts Discovered", styles['CorpHeading2']))
            story.append(Paragraph(", ".join(parsed_data['users']), styles['CorpNormal']))
            story.append(Spacer(1, 0.2*72))
            story.append(PageBreak())
