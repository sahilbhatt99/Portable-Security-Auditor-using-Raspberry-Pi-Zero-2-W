"""
PDF report generator for security audit results.
Creates highly styled, professional corporate PDF reports with findings and recommendations,
incorporating data graphs and educational narrative.
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# Graphics imports for charts
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import HorizontalBarChart

class ReportGenerator:
    """Generates Professional PDF security audit reports"""
    
    def __init__(self, output_path='security_report.pdf'):
        self.output_path = output_path
        self.doc = SimpleDocTemplate(output_path, pagesize=letter,
                                     rightMargin=72, leftMargin=72,
                                     topMargin=72, bottomMargin=72,
                                     allowSplitting=1)
        
        # Custom styles
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(name='CorpTitle', parent=self.styles['Title'], fontName='Helvetica-Bold', fontSize=22, alignment=TA_LEFT, spaceAfter=20, textColor=colors.HexColor('#1f497d')))
        self.styles.add(ParagraphStyle(name='CorpHeading1', parent=self.styles['Heading1'], fontName='Helvetica-Bold', fontSize=16, textColor=colors.HexColor('#1f497d'), spaceBefore=20, spaceAfter=10, borderPadding=5, backColor=colors.HexColor('#f2f2f2')))
        self.styles.add(ParagraphStyle(name='CorpHeading2', parent=self.styles['Heading2'], fontName='Helvetica-Bold', fontSize=14, textColor=colors.HexColor('#2e74b5'), spaceBefore=15, spaceAfter=8))
        self.styles.add(ParagraphStyle(name='CorpNormal', parent=self.styles['Normal'], fontName='Helvetica', fontSize=10, leading=14, spaceAfter=6))
        
        # Educational Text Style
        self.styles.add(ParagraphStyle(name='CorpEducational', parent=self.styles['Normal'], fontName='Helvetica-Oblique', fontSize=9, textColor=colors.HexColor('#555555'), spaceAfter=12))
        
        self.styles.add(ParagraphStyle(name='DangerText', parent=self.styles['Normal'], fontName='Helvetica-Bold', fontSize=10, textColor=colors.firebrick))
        self.styles.add(ParagraphStyle(name='WarningText', parent=self.styles['Normal'], fontName='Helvetica-Bold', fontSize=10, textColor=colors.darkorange))
        
        self.story = []
    
    def generate(self, audit_results):
        """Generate PDF report from audit results"""
        
        self._add_cover_page(audit_results)
        self.story.append(PageBreak())
        
        self._add_executive_summary(audit_results)
        
        summary = audit_results.get('summary', {})
        if 'sysinfo' in summary:
            self._add_sysinfo_section(summary['sysinfo'])
        
        findings = audit_results.get('findings', [])
        if findings:
            self._add_findings_section(findings)
            
        self.story.append(PageBreak())
        self.story.append(Paragraph("DETAILED COMPONENT ANALYSIS", self.styles['CorpHeading1']))
        
        summary = audit_results.get('summary', {})
        
        # 1. Primary User & Access Configuration
        if 'net_users' in summary:
            self._add_accounts_section(summary['net_users'])
            
        # 2. Security Configuration & Enterprise Policy
        if 'hklm_policies' in summary or 'services' in summary:
            self._add_registry_section(summary)
            
        if 'auditpol' in summary:
            self._add_auditpol_section(summary['auditpol'])
            
        # Unified Security Policy & Context
        if any(k in summary for k in ['secpol', 'gpresult_user', 'gpresult_computer']):
            self._add_unified_security_context(summary)
            
        if 'gp_cache' in summary:
            self._add_gp_cache_section(summary['gp_cache'])
            
        # 3. Security Software Status
        if 'defender' in summary:
            self._add_defender_section(summary['defender'])
            
        # 4. Large Data Inventory Dumps (At the bottom)
        if 'drivers' in summary:
            self._add_drivers_section(summary['drivers'])
        if 'devices' in summary:
            self._add_devices_section(summary['devices'])
        if 'firewall' in summary:
            self._add_firewall_section(summary['firewall'])
        
        # Build PDF
        self.doc.build(self.story)
        return self.output_path

    def _add_cover_page(self, audit_results):
        self.story.append(Spacer(1, 2*inch))
        self.story.append(Paragraph("SYSTEM SECURITY AUDIT", self.styles['CorpTitle']))
        self.story.append(Paragraph("CONFIDENTIAL REPORT", ParagraphStyle(name='Subtitle', parent=self.styles['Title'], fontName='Helvetica', fontSize=14, alignment=TA_LEFT, textColor=colors.gray)))
        self.story.append(Spacer(1, 1*inch))
        
        score = self._get_risk_score(audit_results)
        risk_color = colors.firebrick if score > 50 else (colors.darkorange if score > 20 else colors.forestgreen)
        risk_text = f"<font color='{risk_color.hexval()}'><b>{score}/100</b></font>"
        
        meta_data = [
            ['Report Date:', audit_results.get('timestamp', 'N/A')],
            ['Target Host:', audit_results.get('hostname', 'Unknown')],
            ['Calculated Risk Score:', Paragraph(risk_text, self.styles['Normal'])]
        ]
        
        meta_table = Table(meta_data, colWidths=[2.0*inch, 4.5*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e6e6e6')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#333333')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
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
            
            # Analyze severities for Pie Chart
            high_count = 0
            for f in findings:
                if isinstance(f, dict):
                    if f.get('severity', 'HIGH') == 'HIGH' or f.get('severity', 'HIGH') == 'CRITICAL':
                        high_count += 1
                elif isinstance(f, str):
                    if 'disabled' in f.lower() or 'disabling' in f.lower() or 'unquoted' in f.lower() or 'exposed' in f.lower():
                        high_count += 1
                        
            med_count = len(findings) - high_count
            self._add_severity_pie_chart(high_count, med_count)
            
        else:
            self.story.append(Paragraph("System appears generally secure. No critical security issues detected.", self.styles['CorpNormal']))
            
        self.story.append(Spacer(1, 0.2*inch))

    def _add_severity_pie_chart(self, high_count, med_count):
        """Draws a Pie Chart displaying vulnerability severity ratio"""
        d = Drawing(400, 160)
        pc = Pie()
        pc.x = 125
        pc.y = 20
        pc.width = 120
        pc.height = 120
        
        data = []
        labels = []
        if high_count > 0:
            data.append(high_count)
            labels.append(f"HIGH ({high_count})")
        if med_count > 0:
            data.append(med_count)
            labels.append(f"MEDIUM ({med_count})")
            
        pc.data = data
        pc.labels = labels
        pc.slices.strokeWidth = 0.5
        
        # Color mapping: 0=High(Red), 1=Med(Orange) 
        idx = 0
        if high_count > 0:
            pc.slices[idx].fillColor = colors.firebrick
            idx += 1
        if med_count > 0:
            pc.slices[idx].fillColor = colors.darkorange
            
        d.add(pc)
        self.story.append(d)
        self.story.append(Spacer(1, 0.2*inch))

    def _add_sysinfo_section(self, sysinfo):
        self.story.append(Paragraph("SYSTEM SPECIFICATIONS", self.styles['CorpHeading2']))
        
        if 'error' in sysinfo:
            self.story.append(Paragraph(f"Error: {sysinfo['error']}", self.styles['DangerText']))
            return
            
        data = [
            ['Hostname:', Paragraph(sysinfo.get('hostname', 'Unknown'), self.styles['CorpNormal'])],
            ['Current User:', Paragraph(sysinfo.get('user', 'Unknown'), self.styles['CorpNormal'])],
            ['Operating System:', Paragraph(sysinfo.get('os', 'Unknown'), self.styles['CorpNormal'])]
        ]
        table = Table(data, colWidths=[2*inch, 4.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f9f9f9')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        self.story.append(table)
        self.story.append(Spacer(1, 0.3*inch))

    def _add_findings_section(self, findings):
        if not findings:
            return
            
        self.story.append(Paragraph("SECURITY FINDINGS & ANOMALIES", self.styles['CorpHeading2']))
        
        structured = [f for f in findings if isinstance(f, dict)]
        general = [f for f in findings if isinstance(f, str)]
        
        if structured:
            self.story.append(Paragraph("Critical & High Vulnerabilities", self.styles['CorpHeading2']))
            for f in structured:
                title = f.get('title', 'Unknown finding')
                sev = f.get('severity', 'HIGH')
                desc = f.get('description', '')
                evidence = f.get('evidence', '').replace('\\n', '<br/>')
                impact = f.get('impact', '')
                rec = f.get('recommendation', '')
                
                if sev == 'CRITICAL':
                    sev_p = Paragraph(f"<font color='red'><b>{sev}</b></font>", self.styles['CorpNormal'])
                elif sev == 'HIGH':
                    sev_p = Paragraph(f"<font color='orange'><b>{sev}</b></font>", self.styles['CorpNormal'])
                elif sev == 'MED':
                    sev_p = Paragraph(f"<font color='blue'><b>{sev}</b></font>", self.styles['CorpNormal'])
                else:
                    sev_p = Paragraph(f"<b>{sev}</b>", self.styles['CorpNormal'])
                    
                card_data = [
                    [Paragraph(f"<b>{title}</b>", self.styles['CorpNormal']), sev_p],
                    [Paragraph("<b>Description:</b>", self.styles['CorpNormal']), Paragraph(desc, self.styles['CorpNormal'])],
                    [Paragraph("<b>Evidence:</b>", self.styles['CorpNormal']), Paragraph(evidence, self.styles['CorpNormal'])],
                    [Paragraph("<b>Impact:</b>", self.styles['CorpNormal']), Paragraph(impact, self.styles['CorpNormal'])],
                    [Paragraph("<b>Recommendation:</b>", self.styles['CorpNormal']), Paragraph(rec, self.styles['CorpNormal'])]
                ]
                
                card = Table(card_data, colWidths=[1.5*inch, 5*inch])
                card.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f2f2f2')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                self.story.append(KeepTogether([card, Spacer(1, 0.2*inch)]))
                
        if general:
            self.story.append(Spacer(1, 0.1*inch))
            self.story.append(Paragraph("General Anomalies", self.styles['CorpHeading2']))
            data = [['Severity', 'Description']]
            for finding in general:
                if 'disabled' in finding.lower() or 'disabling' in finding.lower() or 'unquoted' in finding.lower() or 'exposed' in finding.lower():
                    severity = Paragraph("<b>HIGH</b>", self.styles['DangerText'])
                else:
                    severity = Paragraph("<b>MEDIUM</b>", self.styles['WarningText'])
                    
                data.append([severity, Paragraph(finding, self.styles['CorpNormal'])])
                
            table = Table(data, colWidths=[1.2*inch, 5.3*inch], repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f497d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ('BOX', (0, 0), (-1, -1), 0.25, colors.grey),
            ]))
            self.story.append(KeepTogether([table, Spacer(1, 0.3*inch)]))

    def _add_defender_section(self, defender):
        self.story.append(Paragraph("Windows Defender Intelligence", self.styles['CorpHeading2']))
        
        ed_text = "Windows Defender is the primary line of defense against malicious execution. Disabling Real-time Protection or Behavior Monitoring fully exposes the host to immediate payload execution, ransomware encryption, and persistent backdoors without administrative intervention."
        self.story.append(Paragraph(ed_text, self.styles['CorpEducational']))
        
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

        # Add all settings
        all_s = defender.get('all_settings', [])
        if all_s:
            self.story.append(Spacer(1, 0.2*inch))
            self.story.append(Paragraph("Complete Defender Settings Dump", self.styles['CorpHeading2']))
            def_data = [['Setting', 'Value', 'Description']]
            for s in all_s:
                val_str = str(s.get('value', ''))
                if len(val_str) > 120:
                    val_str = val_str[:117] + '...'
                def_data.append([
                    Paragraph(s.get('setting', '')[:100], self.styles['CorpNormal']),
                    Paragraph(val_str, self.styles['CorpNormal']),
                    Paragraph(s.get('description', '')[:150], self.styles['CorpNormal'])
                ])
            def_table = Table(def_data, colWidths=[2.2*inch, 2.3*inch, 2.0*inch], repeatRows=1)
            def_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f497d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            self.story.append(def_table)
            self.story.append(Spacer(1, 0.3*inch))

    def _add_drivers_section(self, drivers):
        self.story.append(Paragraph("Kernel Driver Integrity", self.styles['CorpHeading2']))
        
        ed_text = "Digital Signatures cryptographically verify that kernel-level software originates from a trusted publisher. Unsigned drivers present a catastrophic risk, as malware frequently exploits them or installs custom unsigned drivers to operate a Rootkit deep within the OS kernel, bypassing antivirus hooks."
        self.story.append(Paragraph(ed_text, self.styles['CorpEducational']))
        
        if 'error' in drivers:
            self.story.append(Paragraph(f"Error: {drivers['error']}", self.styles['DangerText']))
            return
            
        td = drivers.get('total_drivers', 0)
        ud = drivers.get('unsigned_count', 0)
        
        # Add visual Bar Chart for Drivers
        self._add_horizontal_bar(title="Driver Health", good_val=td-ud, bad_val=ud)
        
        data = [
            ['Total Drivers Enumerated:', str(td)],
            ['Unsigned Drivers Count:', Paragraph(str(ud), self.styles['DangerText'] if ud > 0 else self.styles['CorpNormal'])]
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
        
        # Add detailed drivers table
        detailed = drivers.get('detailed_drivers', [])
        if detailed:
            self.story.append(Spacer(1, 0.2*inch))
            self.story.append(Paragraph("Full Driver Inventory", self.styles['CorpHeading2']))
            driver_data = [['Name', 'Provider', 'Signed']]
            for d in detailed:
                if any(str(v).upper() == 'N/A' for v in d.values()):
                    continue
                driver_data.append([
                    Paragraph(d.get('published_name', ''), self.styles['CorpNormal']),
                    Paragraph(d.get('provider', ''), self.styles['CorpNormal']),
                    Paragraph(str(d.get('signed', '')), self.styles['CorpNormal'])
                ])
            driver_table = Table(driver_data, colWidths=[3.2*inch, 2.3*inch, 1*inch], repeatRows=1)
            driver_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f497d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            self.story.append(driver_table)
            self.story.append(Spacer(1, 0.3*inch))
        
    def _add_horizontal_bar(self, title, good_val, bad_val):
        """Draws a horizontal bar chart summarizing asset integrity"""
        # Minimum Drawing height to prevent empty overlap
        d = Drawing(400, 100)
        bc = HorizontalBarChart()
        bc.x = 80
        bc.y = 20
        bc.height = 60
        bc.width = 300
        
        # Data format expects multiple series across categories. 
        # We'll map Series 0 -> Normal, Series 1 -> Vulnerable
        bc.data = [[good_val], [bad_val]] 
        bc.categoryAxis.categoryNames = [title]
        bc.bars[0].fillColor = colors.HexColor('#1f497d')  # Series 0 (Good)
        bc.bars[1].fillColor = colors.firebrick            # Series 1 (Bad)
        
        # Ensure the scale works even if values are zero
        bc.valueAxis.valueMin = 0
        total = good_val + bad_val
        bc.valueAxis.valueMax = max(total * 1.1, 10) 
        
        d.add(bc)
        self.story.append(d)

    def _add_devices_section(self, devices):
        self.story.append(Paragraph("Hardware Devices State", self.styles['CorpHeading2']))
        
        ed_text = "Hardware devices reporting failure or error codes (such as Code 10 or Code 43) can indicate failing physical hardware, corrupt driver mapping states, or maliciously tampered peripherals interacting dangerously with the host."
        self.story.append(Paragraph(ed_text, self.styles['CorpEducational']))
        
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
        
        # Add detailed devices table
        detailed = devices.get('detailed_devices', [])
        if detailed:
            self.story.append(Spacer(1, 0.2*inch))
            self.story.append(Paragraph("Full Device Inventory", self.styles['CorpHeading2']))
            device_data = [['Description', 'Instance ID', 'Status', 'Problem']]
            for d in detailed:
                if any(str(v).upper() == 'N/A' for v in d.values()):
                    continue
                device_data.append([
                    Paragraph(d.get('description', ''), self.styles['CorpNormal']),
                    Paragraph(d.get('instance_id', ''), self.styles['CorpNormal']),
                    Paragraph(d.get('status', ''), self.styles['CorpNormal']),
                    Paragraph(str(d.get('problem_code', '')), self.styles['CorpNormal'])
                ])
            device_table = Table(device_data, colWidths=[2.5*inch, 2.5*inch, 0.8*inch, 0.7*inch], repeatRows=1)
            device_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f497d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            self.story.append(device_table)
            self.story.append(Spacer(1, 0.3*inch))

    def _add_firewall_section(self, firewall):
        self.story.append(Paragraph("Network Firewall Perimeters", self.styles['CorpHeading2']))
        
        ed_text = "The Windows Firewall dictates network exposure. Permitting inbound traffic on the 'Public' untrusted profile for sensitive administrative ports (such as SMB/445 or RDP/3389) trivially exposes the host to remote exploitation mapping and automated brute-force attacks across untrusted networks."
        self.story.append(Paragraph(ed_text, self.styles['CorpEducational']))
        
        if 'error' in firewall:
            self.story.append(Paragraph(f"Error: {firewall['error']}", self.styles['DangerText']))
            return
        
        all_rules = firewall.get('all_rules', [])
        if all_rules:
            self.story.append(Spacer(1, 0.2*inch))
            self.story.append(Paragraph("All Firewall Rules", self.styles['CorpHeading2']))
            fw_data = [['Name', 'Action', 'Direction', 'Port', 'Severity']]
            for r in all_rules:
                if any(str(v).upper() == 'N/A' for v in r.values()):
                    continue
                sev_c = self.styles['DangerText'] if r.get('severity') == 'HIGH' else self.styles['CorpNormal']
                fw_data.append([
                    Paragraph(r.get('name', ''), self.styles['CorpNormal']),
                    Paragraph(r.get('action', ''), self.styles['CorpNormal']),
                    Paragraph(r.get('direction', ''), self.styles['CorpNormal']),
                    Paragraph(r.get('localport', ''), self.styles['CorpNormal']),
                    Paragraph(r.get('severity', ''), sev_c)
                ])
            fw_table = Table(fw_data, colWidths=[2.5*inch, 0.8*inch, 0.8*inch, 1.4*inch, 1*inch], repeatRows=1)
            fw_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f497d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            self.story.append(fw_table)
            self.story.append(Spacer(1, 0.3*inch))

    def _add_registry_section(self, summary):
        self.story.append(Paragraph("Registry & Local Services", self.styles['CorpHeading2']))
        
        ed_text = "The Windows Registry controls core OS operational behavior. We have performed an automated anomaly scan explicitly looking for UAC Bypasses, disabled LSA Protection, RDP exposure, WDigest memory storage, and IFEO backdoor injections. Any identified anomalies are cataloged securely in the Executive Findings report."
        self.story.append(Paragraph(ed_text, self.styles['CorpEducational']))
        
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
        
        # Registry tables have been dropped per request; 
        # scanning occurs in the background and anomalies are logged to Findings.

    def _add_auditpol_section(self, auditpol):
        self.story.append(Paragraph("Advanced Audit Policies (AuditPol)", self.styles['CorpHeading2']))
        if 'error' in auditpol:
            self.story.append(Paragraph(f"Error: {auditpol['error']}", self.styles['DangerText']))
            return
            
        policies = auditpol.get('policies', [])
        if not policies:
            return
            
        data = [['Policy Category', 'Setting']]
        for p in policies:
            name = p.get('name', '')
            setting = p.get('setting', '')
            if name.upper() == 'N/A' or setting.upper() == 'N/A':
                continue
            if setting == 'No Auditing':
                val = Paragraph(setting, self.styles['WarningText'])
            else:
                val = Paragraph(setting, self.styles['CorpNormal'])
            data.append([Paragraph(name, self.styles['CorpNormal']), val])
            
        table = Table(data, colWidths=[3.5*inch, 1.5*inch], repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f497d')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        self.story.append(table)
        self.story.append(Spacer(1, 0.3*inch))

    def _add_accounts_section(self, net_users):
        self.story.append(Paragraph("Local Accounts", self.styles['CorpHeading2']))
        if 'error' in net_users:
            self.story.append(Paragraph(f"Error: {net_users['error']}", self.styles['DangerText']))
            return
            
        users = net_users.get('users', [])
        self.story.append(Paragraph(", ".join(users), self.styles['CorpNormal']))
        self.story.append(Spacer(1, 0.3*inch))
        
    def _add_gp_cache_section(self, gp_cache):
        self.story.append(Paragraph("Group Policy Cache", self.styles['CorpHeading2']))
        if 'error' in gp_cache:
            self.story.append(Paragraph(f"Note: {gp_cache['error']}", self.styles['CorpNormal']))
            self.story.append(Spacer(1, 0.3*inch))
            return
            
        count = gp_cache.get('cache_count', 0)
        self.story.append(Paragraph(f"Found <b>{count}</b> cached Group Policy objects residing locally on disk.", self.styles['CorpNormal']))
        self.story.append(Spacer(1, 0.3*inch))

    def _add_unified_security_context(self, summary):
        self.story.append(Paragraph("Unified Security Policy & Context Analysis", self.styles['CorpHeading2']))
        
        # Aggregate Risk
        secpol = summary.get('secpol', {})
        gpu = summary.get('gpresult_user', {})
        gpc = summary.get('gpresult_computer', {})
        
        risks = [secpol.get('overall_risk', 'LOW'), gpu.get('risk', 'LOW'), gpc.get('risk', 'LOW')]
        agg_risk = 'LOW'
        if 'CRITICAL' in risks:
            agg_risk = 'CRITICAL'
        elif 'HIGH' in risks:
            agg_risk = 'HIGH'
            
        risk_style = self.styles['DangerText'] if agg_risk in ['CRITICAL', 'HIGH'] else self.styles['CorpNormal']
        self.story.append(Paragraph(f"<b>Aggregate Baseline Risk:</b> {agg_risk}", risk_style))
        self.story.append(Spacer(1, 0.1*inch))
        
        # Display Combined Context (User & Privileges)
        for scope_name, gp_data in [('User Context', gpu), ('Computer Context', gpc)]:
            if not gp_data: continue
            
            user_info = gp_data.get('user_info', {})
            if user_info:
                info_str = f"<b>{scope_name}:</b> {user_info.get('username', 'N/A')} | <b>Profile:</b> {user_info.get('profile_path', 'N/A')} | <b>OS:</b> {user_info.get('os_version', 'N/A')}"
                self.story.append(Paragraph(info_str, self.styles['CorpNormal']))
                self.story.append(Spacer(1, 0.1*inch))
            
            groups = gp_data.get('groups', [])
            if groups:
                self.story.append(Paragraph("<b>Security Groups:</b>", self.styles['CorpNormal']))
                group_list = ", ".join(groups)
                self.story.append(Paragraph(group_list, self.styles['CorpNormal']))
                self.story.append(Spacer(1, 0.1*inch))
                
            privileges = gp_data.get('privileges', [])
            if privileges:
                self.story.append(Paragraph("<b>Assigned Privileges:</b>", self.styles['CorpNormal']))
                for p in privileges:
                    style = self.styles['DangerText'] if p in ["SeDebugPrivilege", "SeImpersonatePrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"] else self.styles['CorpNormal']
                    self.story.append(Paragraph(f"• {p}", style))
                self.story.append(Spacer(1, 0.2*inch))
                
            findings = gp_data.get('findings', [])
            if findings:
                self.story.append(Paragraph(f"<b>{scope_name} Findings:</b>", self.styles['CorpNormal']))
                for f in findings:
                    self.story.append(Paragraph(f"• {f}", self.styles['DangerText'] if "CRITICAL" in f or "HIGH" in f else self.styles['CorpNormal']))
                self.story.append(Spacer(1, 0.2*inch))
        
        # Display Combined Applied GPOs
        combined_gpos = []
        if gpu and gpu.get('gpos'): combined_gpos.extend(gpu['gpos'])
        if gpc and gpc.get('gpos'): combined_gpos.extend(gpc['gpos'])

        if combined_gpos:
            self.story.append(Paragraph(f"<b>Applied Group Policy Objects ({len(combined_gpos)} total)</b>", self.styles['CorpHeading2']))
            data = [['#', 'GPO Name', 'Scope', 'Status']]
            for row in combined_gpos:
                status = str(row.get('status', ''))
                name = str(row.get('name', ''))
                if status.upper() == 'N/A' or name.upper() == 'N/A':
                    continue
                status_style = self.styles['DangerText'] if 'Not Applied' in status else self.styles['CorpNormal']
                data.append([
                    Paragraph(str(row.get('order', '-')), self.styles['CorpNormal']),
                    Paragraph(name, self.styles['CorpNormal']),
                    Paragraph(str(row.get('scope', '')), self.styles['CorpNormal']),
                    Paragraph(status, status_style),
                ])
                
            gpo_table = Table(data, colWidths=[0.4*inch, 3.1*inch, 1*inch, 2*inch], repeatRows=1)
            gpo_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f497d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            self.story.append(gpo_table)
            self.story.append(Spacer(1, 0.3*inch))
        else:
            self.story.append(Paragraph("No Active GPOs Detected. Dumping explicit Local Security Policy configurations.", self.styles['CorpEducational']))
            self.story.append(Spacer(1, 0.2*inch))
            
            # Print SecPol details only in the absence of GPOs
            categories = secpol.get('categories', [])
            if categories:
                for group in categories:
                    items = group.get('items', [])
                    if not items: continue
                    
                    cat_name = group.get('name', 'Unknown category')
                    cat_risk = group.get('risk', 'LOW')
                    
                    # Print Category header with Risk
                    self.story.append(Paragraph(f"Local Policy: {cat_name} (Risk: {cat_risk})", self.styles['CorpHeading2']))
                    
                    # Print Findings & Recommendations
                    findings = group.get('findings', [])
                    recs = group.get('recommendations', [])
                    if findings:
                        self.story.append(Paragraph("<b>Findings:</b>", self.styles['CorpNormal']))
                        for f in findings:
                            self.story.append(Paragraph(f"• {f}", self.styles['DangerText']))
                        self.story.append(Spacer(1, 0.05*inch))
                    
                    if recs:
                        self.story.append(Paragraph("<b>Recommendations:</b>", self.styles['CorpNormal']))
                        for r in recs:
                            self.story.append(Paragraph(f"• {r}", self.styles['CorpEducational']))
                        self.story.append(Spacer(1, 0.1*inch))
                        
                    # Print raw table
                    data = [['Setting', 'Value']]
                    for it in items:
                        if str(it.get('key', '')).upper() == 'N/A' or str(it.get('value', '')).upper() == 'N/A':
                            continue
                        data.append([Paragraph(it['key'], self.styles['CorpNormal']), Paragraph(str(it['value'])[:100], self.styles['CorpNormal'])])
                        
                    table = Table(data, colWidths=[3*inch, 2*inch], repeatRows=1)
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e6e6e6')),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    self.story.append(table)
                    self.story.append(Spacer(1, 0.2*inch))
        
        self.story.append(Spacer(1, 0.3*inch))

    def _add_recommendations(self, audit_results):
        self.story.append(Paragraph("ACTIONABLE RECOMMENDATIONS", self.styles['CorpHeading1']))
        recommendations = []
        findings = audit_results.get('findings', [])
        
        for finding in findings:
            finding_text = finding.get('title', '') + " " + finding.get('description', '') if isinstance(finding, dict) else finding
            
            if 'Real-time protection' in finding_text:
                recommendations.append("Immediately enable Windows Defender Real-time Protection to defend against runtime execution.")
            elif 'Anti-spyware' in finding_text:
                recommendations.append("Enable Windows Defender Anti-spyware module.")
            elif 'Unsigned driver' in finding_text:
                recommendations.append("Review unsigned drivers identified; sandbox them or replace with strictly digitally verified equivalents.")
            elif 'Problematic device' in finding_text:
                recommendations.append("Investigate hardware component errors via Device Manager GUI mapping.")
            elif 'Unquoted Service Path' in finding_text:
                recommendations.append("Patch vulnerable unquoted service paths by modifying the registry ImagePath string to encapsulate the absolute path in double-quotes.")
            elif 'policy' in finding_text.lower() and 'disabled' in finding_text.lower():
                recommendations.append("Re-enable critical administrative tools (Task Manager/RegEdit/CMD).")
            elif 'Exposed Firewall Rule' in finding_text:
                recommendations.append("Close unnecessary public inbound firewall profile ports (ex. 3389, 445, 5985).")
            elif 'Missing Audit Policy' in finding_text:
                recommendations.append("Enable Success/Failure tracking for critical system Audit Policies to ensure forensics visibility.")
        
        if not recommendations:
            recommendations.append("Continue monitoring system security settings regularly.")
            recommendations.append("Enforce principle of least privilege.")
            
        for i, rec in enumerate(set(recommendations), 1):
            self.story.append(Paragraph(f"{i}. {rec}", self.styles['CorpNormal']))

    def _get_risk_score(self, audit_results):
        """Calculate custom risk score 0-100"""
        score = 0
        findings = audit_results.get('findings', [])
        
        score += len(findings) * 20
        
        summary = audit_results.get('summary', {})
        defender = summary.get('defender', {})
        if not defender.get('realtime_enabled', True):
            score += 40
            
        return int(min(score, 100))
