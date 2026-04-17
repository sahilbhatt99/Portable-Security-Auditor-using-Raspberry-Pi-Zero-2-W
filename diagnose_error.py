import traceback
import sys

print("Diagnosing KeepTogether...")
try:
    from reportlab.platypus import KeepTogether
    print("SUCCESS: KeepTogether is successfully imported from reportlab.platypus!")
except Exception as e:
    print(f"FAILED IMPORT: {e}")

try:
    from parser.report_generator import ReportGenerator
    from parser.audit_parser import AuditParser
    print("SUCCESS: Local modules imported successfully!")
    
    # Force a dummy execution to see where NameError triggers
    r = ReportGenerator()
    dummy_findings = {'findings': [{'title': 'Test', 'severity': 'HIGH', 'description': 'Test', 'evidence': 'Test'}]}
    r._add_findings_section(dummy_findings)
    print("SUCCESS: _add_findings_section executed properly!")
except Exception as e:
    print("================ FAULT FOUND ================")
    traceback.print_exc()
    print("==============================================")
