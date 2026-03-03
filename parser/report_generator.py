"""
PDF report generator for security audit results.
Creates formatted PDF reports with findings and recommendations.
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from datetime import datetime


class ReportGenerator:
    """Generates PDF security audit reports"""
    
    def __init__(self, output_path='security_report.pdf'):
        self.output_path = output_path
        self.doc = SimpleDocTemplate(output_path, pagesize=letter)
        self.styles = getSampleStyleSheet()
        self.story = []
    
    def generate(self, audit_results):
        """Generate PDF report from audit results"""
        
        # Title
        title = Paragraph("<b>SECURITY AUDIT REPORT</b>", self.styles['Title'])
        self.story.append(title)
        self.story.append(Spacer(1, 0.3*inch))
        
        # Metadata
        meta_data = [
            ['Report Date:', audit_results.get('timestamp', 'N/A')],
            ['Hostname:', audit_results.get('hostname', 'Unknown')],
            ['Risk Score:', f"{self._get_risk_score(audit_results)}/100"]
        ]
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ]))
        self.story.append(meta_table)
        self.story.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        self.story.append(Paragraph("<b>EXECUTIVE SUMMARY</b>", self.styles['Heading1']))
        findings = audit_results.get('findings', [])
        if findings:
            summary_text = f"Analysis identified {len(findings)} security findings requiring attention."
            self.story.append(Paragraph(summary_text, self.styles['Normal']))
        else:
            self.story.append(Paragraph("No critical security issues detected.", self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Findings
        if findings:
            self.story.append(Paragraph("<b>SECURITY FINDINGS</b>", self.styles['Heading1']))
            for i, finding in enumerate(findings, 1):
                self.story.append(Paragraph(f"{i}. {finding}", self.styles['Normal']))
            self.story.append(Spacer(1, 0.2*inch))
        
        # Detailed Analysis
        self.story.append(Paragraph("<b>DETAILED ANALYSIS</b>", self.styles['Heading1']))
        summary = audit_results.get('summary', {})
        
        # Defender
        if 'defender' in summary:
            self._add_defender_section(summary['defender'])
        
        # Drivers
        if 'drivers' in summary:
            self._add_drivers_section(summary['drivers'])
        
        # Devices
        if 'devices' in summary:
            self._add_devices_section(summary['devices'])
        
        # Registry
        if 'hklm_policies' in summary or 'services' in summary:
            self._add_registry_section(summary)
        
        # Firewall
        if 'firewall' in summary:
            self._add_firewall_section(summary['firewall'])
        
        # Recommendations
        self.story.append(PageBreak())
        self.story.append(Paragraph("<b>RECOMMENDATIONS</b>", self.styles['Heading1']))
        recommendations = self._generate_recommendations(audit_results)
        for i, rec in enumerate(recommendations, 1):
            self.story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
        
        # Build PDF
        self.doc.build(self.story)
        return self.output_path
    
    def _add_defender_section(self, defender):
        """Add Windows Defender section"""
        self.story.append(Paragraph("<b>Windows Defender</b>", self.styles['Heading2']))
        
        if 'error' in defender:
            self.story.append(Paragraph(f"Error: {defender['error']}", self.styles['Normal']))
        else:
            data = [
                ['Real-time Protection', 'Enabled' if defender.get('realtime_enabled') else 'DISABLED'],
                ['Anti-spyware', 'Enabled' if defender.get('antispyware_enabled') else 'DISABLED'],
                ['Behavior Monitoring', 'Enabled' if defender.get('behavior_monitoring') else 'DISABLED']
            ]
            table = Table(data, colWidths=[3*inch, 2*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            self.story.append(table)
            
            # Add detailed settings
            if 'all_settings' in defender:
                self.story.append(Spacer(1, 0.1*inch))
                self.story.append(Paragraph("Detailed Settings:", self.styles['Heading3']))
                for setting in defender['all_settings'][:30]:
                    self.story.append(Paragraph(
                        f"• {setting['setting']}: {setting['value']}<br/>&nbsp;&nbsp;{setting['description']}",
                        self.styles['Normal']
                    ))
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def _add_drivers_section(self, drivers):
        """Add drivers section"""
        self.story.append(Paragraph("<b>Installed Drivers</b>", self.styles['Heading2']))
        
        if 'error' in drivers:
            self.story.append(Paragraph(f"Error: {drivers['error']}", self.styles['Normal']))
        else:
            data = [
                ['Total Drivers', str(drivers.get('total_drivers', 0))],
                ['Unsigned Drivers', str(drivers.get('unsigned_count', 0))]
            ]
            table = Table(data, colWidths=[3*inch, 2*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            self.story.append(table)
            
            # Add detailed driver list
            if 'detailed_drivers' in drivers:
                self.story.append(Spacer(1, 0.1*inch))
                self.story.append(Paragraph("Driver Details:", self.styles['Heading3']))
                for driver in drivers['detailed_drivers'][:30]:
                    status = 'Signed' if driver['signed'] else 'UNSIGNED'
                    self.story.append(Paragraph(
                        f"• {driver['published_name']} - {driver['provider']} ({status})",
                        self.styles['Normal']
                    ))
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def _add_devices_section(self, devices):
        """Add devices section"""
        self.story.append(Paragraph("<b>System Devices</b>", self.styles['Heading2']))
        
        if 'error' in devices:
            self.story.append(Paragraph(f"Error: {devices['error']}", self.styles['Normal']))
        else:
            data = [
                ['Total Devices', str(devices.get('total_devices', 0))],
                ['Problem Devices', str(devices.get('problem_count', 0))]
            ]
            table = Table(data, colWidths=[3*inch, 2*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            self.story.append(table)
            
            # Add detailed device list
            if 'detailed_devices' in devices:
                self.story.append(Spacer(1, 0.1*inch))
                self.story.append(Paragraph("Device Details:", self.styles['Heading3']))
                for device in devices['detailed_devices'][:30]:
                    status = 'Problem' if device['has_problem'] else 'OK'
                    self.story.append(Paragraph(
                        f"• {device['description']} ({status})",
                        self.styles['Normal']
                    ))
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def _add_registry_section(self, summary):
        """Add registry section"""
        self.story.append(Paragraph("<b>Registry Analysis</b>", self.styles['Heading2']))
        
        data = []
        if 'hklm_policies' in summary:
            hklm = summary['hklm_policies']
            data.append(['HKLM Policies', str(hklm.get('total_keys', 0)) + ' keys'])
            if 'detailed_entries' in hklm:
                self.story.append(Paragraph("HKLM Policy Entries:", self.styles['Heading3']))
                for entry in hklm['detailed_entries'][:20]:
                    self.story.append(Paragraph(f"• {entry['key']} ({entry['type']})", self.styles['Normal']))
        
        if 'hkcu_policies' in summary:
            hkcu = summary['hkcu_policies']
            data.append(['HKCU Policies', str(hkcu.get('total_keys', 0)) + ' keys'])
            if 'detailed_entries' in hkcu:
                self.story.append(Paragraph("HKCU Policy Entries:", self.styles['Heading3']))
                for entry in hkcu['detailed_entries'][:20]:
                    self.story.append(Paragraph(f"• {entry['key']} ({entry['type']})", self.styles['Normal']))
        
        if 'services' in summary:
            data.append(['Services', str(summary['services'].get('total_keys', 0)) + ' keys'])
        if 'control' in summary:
            data.append(['Control', str(summary['control'].get('total_keys', 0)) + ' keys'])
        
        if data:
            table = Table(data, colWidths=[3*inch, 2*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            self.story.append(table)
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def _add_firewall_section(self, firewall):
        """Add firewall section"""
        self.story.append(Paragraph("<b>Firewall Configuration</b>", self.styles['Heading2']))
        
        if 'error' in firewall:
            self.story.append(Paragraph(f"Error: {firewall['error']}", self.styles['Normal']))
        else:
            self.story.append(Paragraph(f"Configuration exported ({firewall.get('size_bytes', 0)} bytes)", self.styles['Normal']))
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def _generate_recommendations(self, audit_results):
        """Generate recommendations based on findings"""
        recommendations = []
        findings = audit_results.get('findings', [])
        
        for finding in findings:
            if 'Real-time protection' in finding:
                recommendations.append("Enable Windows Defender Real-time Protection immediately")
            elif 'Anti-spyware' in finding:
                recommendations.append("Enable Windows Defender Anti-spyware protection")
            elif 'unsigned drivers' in finding:
                recommendations.append("Review and remove unsigned drivers or obtain signed versions")
            elif 'devices with problems' in finding:
                recommendations.append("Investigate and resolve device driver issues")
        
        if not recommendations:
            recommendations.append("Continue monitoring system security settings regularly")
            recommendations.append("Keep Windows and all software up to date")
            recommendations.append("Maintain regular security audits")
        
        return recommendations
    
    def _get_risk_score(self, audit_results):
        """Calculate risk score"""
        score = 0
        findings = audit_results.get('findings', [])
        score += len(findings) * 15
        
        summary = audit_results.get('summary', {})
        defender = summary.get('defender', {})
        if not defender.get('realtime_enabled', True):
            score += 30
        
        return min(score, 100)
