"""
PDF report generator for security audit results.
Creates highly styled, professional corporate PDF reports with findings and recommendations.
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT

class ReportGenerator:
    """Generates Professional PDF security audit reports"""
    
    def __init__(self, output_path='security_report.pdf'):
        self.output_path = output_path
        self.doc = SimpleDocTemplate(output_path, pagesize=letter,
                                     rightMargin=72, leftMargin=72,
                                     topMargin=72, bottomMargin=72)
        
        # Custom styles
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(name='CorpTitle', parent=self.styles['Title'], fontName='Helvetica-Bold', fontSize=24, spaceAfter=20, textColor=colors.HexColor('#1f497d')))
        self.styles.add(ParagraphStyle(name='CorpHeading1', parent=self.styles['Heading1'], fontName='Helvetica-Bold', fontSize=16, textColor=colors.HexColor('#1f497d'), spaceBefore=20, spaceAfter=10, borderPadding=5, backColor=colors.HexColor('#f2f2f2')))
        self.styles.add(ParagraphStyle(name='CorpHeading2', parent=self.styles['Heading2'], fontName='Helvetica-Bold', fontSize=14, textColor=colors.HexColor('#2e74b5'), spaceBefore=15, spaceAfter=8))
        self.styles.add(ParagraphStyle(name='CorpNormal', parent=self.styles['Normal'], fontName='Helvetica', fontSize=10, leading=14, spaceAfter=6))
        self.styles.add(ParagraphStyle(name='DangerText', parent=self.styles['Normal'], fontName='Helvetica-Bold', fontSize=10, textColor=colors.firebrick))
        self.styles.add(ParagraphStyle(name='WarningText', parent=self.styles['Normal'], fontName='Helvetica-Bold', fontSize=10, textColor=colors.darkorange))
        
        self.story = []
    
    def generate(self, audit_results):
        """Generate PDF report from audit results"""
        
        self._add_cover_page(audit_results)
        self.story.append(PageBreak())
        
        self._add_executive_summary(audit_results)
        
        findings = audit_results.get('findings', [])
        if findings:
            self._add_findings_section(findings)
            
        self.story.append(PageBreak())
        self.story.append(Paragraph("DETAILED ANALYSIS", self.styles['CorpHeading1']))
        
        summary = audit_results.get('summary', {})
        if 'defender' in summary:
            self._add_defender_section(summary['defender'])
        if 'drivers' in summary:
            self._add_drivers_section(summary['drivers'])
        if 'devices' in summary:
            self._add_devices_section(summary['devices'])
        if 'firewall' in summary:
            self._add_firewall_section(summary['firewall'])
        if 'hklm_policies' in summary or 'services' in summary:
            self._add_registry_section(summary)
            
        self.story.append(PageBreak())
        self._add_recommendations(audit_results)
        
        # Build PDF
        self.doc.build(self.story)
        return self.output_path

    def _add_cover_page(self, audit_results):
        self.story.append(Spacer(1, 2*inch))
        self.story.append(Paragraph("SYSTEM SECURITY AUDIT", self.styles['CorpTitle']))
        self.story.append(Paragraph("CONFIDENTIAL REPORT", ParagraphStyle(name='Subtitle', parent=self.styles['Title'], fontName='Helvetica', fontSize=14, textColor=colors.gray)))
        self.story.append(Spacer(1, 1*inch))
        
        score = self._get_risk_score(audit_results)
        risk_color = colors.firebrick if score > 50 else (colors.darkorange if score > 20 else colors.forestgreen)
        risk_text = f"<font color='{risk_color.hexval()}'><b>{score}/100</b></font>"
        
        meta_data = [
            ['Report Date:', audit_results.get('timestamp', 'N/A')],
            ['Target Host:', audit_results.get('hostname', 'Unknown')],
            ['Risk Score:', Paragraph(risk_text, self.styles['Normal'])]
        ]
        
        meta_table = Table(meta_data, colWidths=[2*inch, 3*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e6e6e6')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#333333')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.white),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ]))
        self.story.append(meta_table)

    def _add_executive_summary(self, audit_results):
        self.story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['CorpHeading1']))
        findings = audit_results.get('findings', [])
        
        if findings:
            summary_text = f"This audit identified <b>{len(findings)} security findings or anomalies</b> requiring attention."
            self.story.append(Paragraph(summary_text, self.styles['DangerText']))
        else:
            self.story.append(Paragraph("System appears generally secure. No critical security issues detected.", self.styles['CorpNormal']))
            
        self.story.append(Spacer(1, 0.2*inch))

    def _add_findings_section(self, findings):
        self.story.append(Paragraph("SECURITY FINDINGS & ANOMALIES", self.styles['CorpHeading2']))
        
        data = [['Severity', 'Description']]
        for finding in findings:
            # simple heuristic for severity styling
            if 'disabled' in finding.lower() or 'disabling' in finding.lower() or 'unquoted' in finding.lower() or 'exposed' in finding.lower():
                severity = Paragraph("<b>HIGH</b>", self.styles['DangerText'])
            else:
                severity = Paragraph("<b>MEDIUM</b>", self.styles['WarningText'])
                
            data.append([severity, Paragraph(finding, self.styles['CorpNormal'])])
            
        table = Table(data, colWidths=[1*inch, 5.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f497d')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.grey),
        ]))
        self.story.append(table)
        self.story.append(Spacer(1, 0.3*inch))

    def _add_defender_section(self, defender):
        self.story.append(Paragraph("Windows Defender Status", self.styles['CorpHeading2']))
        
        if 'error' in defender:
            self.story.append(Paragraph(f"Error: {defender['error']}", self.styles['DangerText']))
            return
            
        data = [['Component', 'Status']]
        
        rtp = 'Enabled' if defender.get('realtime_enabled') else 'DISABLED'
        rtp_c = self.styles['CorpNormal'] if defender.get('realtime_enabled') else self.styles['DangerText']
        data.append(['Real-time Protection', Paragraph(rtp, rtp_c)])
        
        as_status = 'Enabled' if defender.get('antispyware_enabled') else 'DISABLED'
        as_c = self.styles['CorpNormal'] if defender.get('antispyware_enabled') else self.styles['DangerText']
        data.append(['Anti-spyware', Paragraph(as_status, as_c)])
        
        bm = 'Enabled' if defender.get('behavior_monitoring') else 'DISABLED'
        bm_c = self.styles['CorpNormal'] if defender.get('behavior_monitoring') else self.styles['DangerText']
        data.append(['Behavior Monitoring', Paragraph(bm, bm_c)])
        
        table = Table(data, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f2f2f2')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        self.story.append(table)
        self.story.append(Spacer(1, 0.2*inch))

    def _add_drivers_section(self, drivers):
        self.story.append(Paragraph("Installed Drivers", self.styles['CorpHeading2']))
        if 'error' in drivers:
            self.story.append(Paragraph(f"Error: {drivers['error']}", self.styles['DangerText']))
            return
            
        data = [
            ['Total Drivers Enumerated:', str(drivers.get('total_drivers', 0))],
            ['Unsigned Drivers Count:', Paragraph(str(drivers.get('unsigned_count', 0)), self.styles['DangerText'] if drivers.get('unsigned_count', 0) > 0 else self.styles['CorpNormal'])]
        ]
        table = Table(data, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f9f9f9')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        self.story.append(table)
        self.story.append(Spacer(1, 0.2*inch))

    def _add_devices_section(self, devices):
        self.story.append(Paragraph("Hardware Devices", self.styles['CorpHeading2']))
        if 'error' in devices:
            self.story.append(Paragraph(f"Error: {devices['error']}", self.styles['DangerText']))
            return
            
        data = [
            ['Total Devices Enumerated:', str(devices.get('total_devices', 0))],
            ['Problem Devices Count:', Paragraph(str(devices.get('problem_count', 0)), self.styles['DangerText'] if devices.get('problem_count', 0) > 0 else self.styles['CorpNormal'])]
        ]
        table = Table(data, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f9f9f9')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        self.story.append(table)
        self.story.append(Spacer(1, 0.2*inch))

    def _add_firewall_section(self, firewall):
        self.story.append(Paragraph("Firewall Rules Analysis", self.styles['CorpHeading2']))
        if 'error' in firewall:
            self.story.append(Paragraph(f"Error: {firewall['error']}", self.styles['DangerText']))
            return
        
        self.story.append(Paragraph(f"Parsed {firewall.get('active_rules', 0)} active inbound firewall rules.", self.styles['CorpNormal']))
        self.story.append(Spacer(1, 0.2*inch))

    def _add_registry_section(self, summary):
        self.story.append(Paragraph("Registry & Policy Analysis", self.styles['CorpHeading2']))
        data = [['Hive/Category', 'Key Count']]
        if 'hklm_policies' in summary:
            data.append(['HKLM Policies', str(summary['hklm_policies'].get('total_keys', 0))])
        if 'hkcu_policies' in summary:
            data.append(['HKCU Policies', str(summary['hkcu_policies'].get('total_keys', 0))])
        if 'services' in summary:
            data.append(['Services Config', str(summary['services'].get('total_keys', 0))])
            
        if len(data) > 1:
            table = Table(data, colWidths=[3*inch, 2*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f2f2f2')),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            self.story.append(table)
        self.story.append(Spacer(1, 0.2*inch))

    def _add_recommendations(self, audit_results):
        self.story.append(Paragraph("ACTIONABLE RECOMMENDATIONS", self.styles['CorpHeading1']))
        recommendations = []
        findings = audit_results.get('findings', [])
        
        for finding in findings:
            if 'Real-time protection' in finding:
                recommendations.append("Immediately enable Windows Defender Real-time Protection.")
            elif 'Anti-spyware' in finding:
                recommendations.append("Enable Windows Defender Anti-spyware module.")
            elif 'Unsigned driver' in finding:
                recommendations.append("Review unsigned drivers identified and replace with verified equivalents.")
            elif 'Problematic device' in finding:
                recommendations.append("Investigate hardware component errors via Device Manager.")
            elif 'Unquoted Service Path' in finding:
                recommendations.append("Patch vulnerable unquoted service paths by modifying the registry ImagePath string to include quotes.")
            elif 'policy' in finding.lower() and 'disabled' in finding.lower():
                recommendations.append("Re-enable critical administrative tools (Task Manager/RegEdit/CMD).")
            elif 'Exposed Firewall Rule' in finding:
                recommendations.append("Close unnecessary public inbound firewall ports (ex. 3389, 445).")
        
        if not recommendations:
            recommendations.append("Continue monitoring system security settings regularly.")
            recommendations.append("Enforce principle of least privilege.")
            
        for i, rec in enumerate(set(recommendations), 1):
            self.story.append(Paragraph(f"{i}. {rec}", self.styles['CorpNormal']))

    def _get_risk_score(self, audit_results):
        """Calculate custom risk score 0-100"""
        score = 0
        findings = audit_results.get('findings', [])
        
        # Heavy weighting for vulnerabilities
        score += len(findings) * 20
        
        summary = audit_results.get('summary', {})
        defender = summary.get('defender', {})
        if not defender.get('realtime_enabled', True):
            score += 40
            
        return int(min(score, 100))
