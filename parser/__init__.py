"""
Security Audit Parser Package.
Parses Windows audit files and generates PDF reports.
"""

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
    
    generator = ReportGenerator(output_pdf)
    report_path = generator.generate(results)
    
    return report_path
