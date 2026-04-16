from parser.audit_parser import AuditParser
from parser.report_generator import ReportGenerator
import json
import sys

def main():
    base_path = 'c:\\Users\\99sah\\usb gadget\\testdata 2\\pro'
    print(f"Running against {base_path}...")
    
    parser = AuditParser()
    results = parser.analyze_all(base_path)
    
    print(f"Risk Score: {parser.get_risk_score()}")
    print("Detected Summary Keys: ", results.get('summary', {}).keys())
    
    reporter = ReportGenerator('test_pro_report.pdf')
    try:
        output = reporter.generate(results)
        print(f"Successfully generated {output}")
    except Exception as e:
        print(f"Error generating PDF: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
