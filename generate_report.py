#!/usr/bin/env python3
"""
Standalone CLI tool for generating security audit reports.
Usage: python generate_report.py [base_path] [output_pdf]
"""

import sys
from parser import generate_report

if __name__ == '__main__':
    base_path = sys.argv[1] if len(sys.argv) > 1 else 'C:\\'
    output_pdf = sys.argv[2] if len(sys.argv) > 2 else 'security_report.pdf'
    
    print(f"Parsing audit files from: {base_path}")
    print(f"Generating report: {output_pdf}")
    
    try:
        report_path = generate_report(base_path, output_pdf)
        print(f"✓ Report generated successfully: {report_path}")
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)
