"""
Security Audit Parser Package.
Parses Windows audit files and generates PDF reports.
"""

import os
from .audit_parser import AuditParser
from .report_generator import ReportGenerator

__all__ = ['AuditParser', 'ReportGenerator']


def generate_report(base_path='C:\\', output_pdf='security_report.pdf'):
    """
    Convenience function to parse audit files and generate report.
    
    Args:
        base_path: Directory containing audit files
        output_pdf: Output PDF filename
    
    Returns:
        Path to generated PDF report
    """
    parser = AuditParser()
    results = parser.analyze_all(base_path)
    
    out_dir = os.path.dirname(output_pdf) or '.'
    out_file = os.path.basename(output_pdf)
    
    generator = ReportGenerator(out_dir)
    report_path = generator.generate(results, out_file)
    
    return report_path
