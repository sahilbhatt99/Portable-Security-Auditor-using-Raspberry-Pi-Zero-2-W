"""
Re-Architected PDF Report Generator mapping natively to Plugin Architecture.
"""
import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie

from parser.plugins.defender_plugin import DefenderPlugin
from parser.plugins.firewall_plugin import FirewallPlugin
from parser.plugins.hardware_plugin import HardwarePlugin
from parser.plugins.net_users_plugin import NetUsersPlugin
from parser.plugins.policy_plugin import PolicyPlugin
from parser.plugins.registry_plugin import RegistryPlugin

class ReportGenerator:
    """Generates PDF traversing modular file Plugins"""
    
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        self.styles = getSampleStyleSheet()
        self._init_styles()
        
    def _init_styles(self):
        self.styles.add(ParagraphStyle(name='CorpTitle', fontName='Helvetica-Bold', fontSize=24, spaceAfter=20, alignment=1, textColor=colors.HexColor('#002060')))
        self.styles.add(ParagraphStyle(name='CorpHeading1', fontName='Helvetica-Bold', fontSize=16, spaceAfter=12, spaceBefore=20, textColor=colors.HexColor('#0f243e'), borderPadding=4, backColor=colors.HexColor('#f2f2f2')))
        self.styles.add(ParagraphStyle(name='CorpHeading2', fontName='Helvetica-Bold', fontSize=14, spaceAfter=10, spaceBefore=16, textColor=colors.HexColor('#1f497d')))
        self.styles.add(ParagraphStyle(name='CorpNormal', fontName='Helvetica', fontSize=10, spaceAfter=6, spaceBefore=4))
        self.styles.add(ParagraphStyle(name='DangerText', parent=self.styles['CorpNormal'], textColor=colors.HexColor('#c00000'), fontName='Helvetica-Bold'))
        self.styles.add(ParagraphStyle(name='CorpEducational', fontName='Helvetica-Oblique', fontSize=9, textColor=colors.gray, spaceAfter=8))
        
    def generate(self, audit_results, output_filename="report.pdf"):
        os.makedirs(self.output_dir, exist_ok=True)
        self.output_path = os.path.join(self.output_dir, output_filename)
        
        self.doc = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            rightMargin=72, leftMargin=72,
            topMargin=72, bottomMargin=18,
            title="System Security Audit"
        )
        
        self.story = []
        
        # 1. Cover Page
        self._add_cover_page(audit_results)
        self.story.append(PageBreak())
        
        # 2. Executive Summary (Vulnerabilities Aggregation)
        self._add_executive_summary(audit_results)
        self._add_findings_section(audit_results)
        self.story.append(PageBreak())
        
        # 3. Modular Details Iteration mappings
        self.story.append(Paragraph("DETAILED COMPONENT ANALYSIS", self.styles['CorpHeading1']))
        self.story.append(Spacer(1, 0.2*inch))
        
        plugin_cache = audit_results.get('summary', {}).get('plugin_cache', {})
        
        # Native order to maintain logical readability
        components = [NetUsersPlugin(), RegistryPlugin(), PolicyPlugin(), DefenderPlugin(), HardwarePlugin(), FirewallPlugin()]
        
        for plugin in components:
            cache_name = plugin.__class__.__name__
            if cache_name in plugin_cache:
                for parsed_instance in plugin_cache[cache_name]:
                    plugin.generate_section(parsed_instance, self.story, self.styles)
        
        self.doc.build(self.story)
        return self.output_path

    def _add_cover_page(self, audit_results):
        self.story.append(Spacer(1, 2*inch))
        self.story.append(Paragraph("SYSTEM SECURITY AUDIT", self.styles['CorpTitle']))
        self.story.append(Spacer(1, 1*inch))
        
        score = self._get_risk_score(audit_results)
        risk_color = colors.firebrick if score > 50 else (colors.darkorange if score > 20 else colors.forestgreen)
        risk_text = f"<font color='{risk_color.hexval()}'><b>{score}/100</b></font>"
        
        meta_data = [
            ['Report Date:', audit_results.get('timestamp', 'N/A')],
            ['Target Host:', audit_results.get('hostname', 'Unknown')],
            ['Calculated Risk Score:', Paragraph(risk_text, self.styles['CorpNormal'])]
        ]
        
        meta_table = Table(meta_data, colWidths=[2.0*inch, 4.5*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e6e6e6')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ]))
        self.story.append(meta_table)

    def _add_executive_summary(self, audit_results):
        self.story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['CorpHeading1']))
        findings = audit_results.get('findings', [])
        
        if findings:
            self.story.append(Paragraph(f"This audit identified <b>{len(findings)} security findings</b> requiring attention.", self.styles['DangerText']))
            high_count = sum(1 for f in findings if isinstance(f, dict) and f.get('severity') in ['CRITICAL', 'HIGH'])
            med_count = len(findings) - high_count
            self._add_severity_pie_chart(high_count, med_count)
        else:
            self.story.append(Paragraph("System appears highly secure. No vulnerabilities detected.", self.styles['CorpNormal']))
            
    def _add_severity_pie_chart(self, high_count, med_count):
        d = Drawing(400, 160)
        pc = Pie()
        pc.x = 125
        pc.y = 20
        pc.width = 120
        pc.height = 120
        
        data = []
        labels = []
        pie_colors = []
        if high_count > 0:
            data.append(high_count)
            labels.append(f"HIGH/CRITICAL ({high_count})")
            pie_colors.append(colors.firebrick)
        if med_count > 0:
            data.append(med_count)
            labels.append(f"LOW/MED ({med_count})")
            pie_colors.append(colors.darkorange)
            
        if data:
            pc.data = data
            pc.labels = labels
            pc.slices.strokeWidth = 0.5
            for i, pc_color in enumerate(pie_colors):
                pc.slices[i].fillColor = pc_color
            d.add(pc)
            self.story.append(d)
        self.story.append(Spacer(1, 0.2*inch))

    def _add_findings_section(self, audit_results):
        findings = audit_results.get('findings', [])
        if not findings: return
            
        self.story.append(Paragraph("SECURITY FINDINGS", self.styles['CorpHeading1']))
        self.story.append(Paragraph("Details regarding configurations extracted iteratively by active plugins mapping against execution scopes.", self.styles['CorpEducational']))
        self.story.append(Spacer(1, 0.2*inch))
        
        for f in findings:
            if isinstance(f, dict):
                card_data = []
                sev = f.get('severity', 'LOW')
                card_data.append([Paragraph(f"<b>{f.get('title', 'Unknown')}</b>", self.styles['CorpNormal']), Paragraph(f"<b>{sev}</b>", self.styles['DangerText'])])
                card_data.append([Paragraph("Description:", self.styles['CorpNormal']), Paragraph(f.get('description', ''), self.styles['CorpNormal'])])
                if f.get('impact'): card_data.append([Paragraph("Impact:", self.styles['CorpNormal']), Paragraph(f.get('impact', ''), self.styles['DangerText'])])
                if f.get('recommendation'): card_data.append([Paragraph("Recommendation:", self.styles['CorpNormal']), Paragraph(f.get('recommendation', ''), self.styles['CorpEducational'])])
                if f.get('evidence'): card_data.append([Paragraph("Evidence:", self.styles['CorpNormal']), Paragraph(f.get('evidence', ''), self.styles['CorpNormal'])])
                
                t = Table(card_data, colWidths=[1.5*inch, 5.0*inch])
                t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e6e6e6')), ('GRID', (0,0), (-1,-1), 0.25, colors.lightgrey), ('VALIGN', (0,0), (-1,-1), 'TOP')]))
                self.story.append(KeepTogether([t, Spacer(1, 0.2*inch)]))

    def _get_risk_score(self, audit_results):
        score = len(audit_results.get('findings', [])) * 20
        return int(min(score, 100))
