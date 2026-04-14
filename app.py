from flask import Flask, render_template, request, jsonify, send_file, Response
from datetime import datetime
import json
import os
from hid import HIDController
from portal.upload_server import start_background, set_scan_metadata
from parser import generate_report

app = Flask(__name__)

# Initialize HID controller
hid_controller = HIDController()

# Start upload server in background
start_background()

# In-memory storage for compliance logs
compliance_logs = []
MAX_LOGS = 100

# System status tracking
def get_system_status():
    hid_status = hid_controller.get_status()
    return {
        "pi_status": "online",
        "usb_link": "connected",
        "policy_engine": "active",
        "hid_enabled": hid_status['enabled'],
        "hid_payloads": hid_status['available_payloads']
    }

@app.route('/')
def index():
    """Render main dashboard"""
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_compliance():
    """Accept system data and return compliance result"""
    try:
        data = request.get_json()
        
        # Basic compliance checks
        issues = []
        compliant = True
        
        # Example checks (expand as needed)
        if data.get('firewall_enabled') == False:
            issues.append("Firewall is disabled")
            compliant = False
        
        if data.get('antivirus_updated') == False:
            issues.append("Antivirus definitions outdated")
            compliant = False
        
        if data.get('disk_encryption') == False:
            issues.append("Disk encryption not enabled")
            compliant = False
        
        # Build response
        result = {
            "compliant": compliant,
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
            "host": data.get('hostname', 'unknown')
        }
        
        # Store in logs
        log_entry = {
            "result": result,
            "raw_data": data,
            "timestamp": datetime.now().isoformat()
        }
        compliance_logs.insert(0, log_entry)
        
        # Keep only last MAX_LOGS entries
        if len(compliance_logs) > MAX_LOGS:
            compliance_logs.pop()
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/status')
def status():
    """Return server health status"""
    return jsonify({
        "status": "healthy",
        "uptime": "running",
        "system": get_system_status(),
        "logs_count": len(compliance_logs),
        "timestamp": datetime.now().isoformat()
    })

@app.route('/logs')
def logs():
    """Return recent compliance logs"""
    return jsonify({
        "logs": compliance_logs[:50],  # Return last 50 logs
        "total": len(compliance_logs)
    })

# HID Control Routes

@app.route('/hid/enable', methods=['POST'])
def hid_enable():
    """Enable HID injection system"""
    result = hid_controller.enable_hid()
    return jsonify(result)

@app.route('/hid/disable', methods=['POST'])
def hid_disable():
    """Disable HID injection system"""
    result = hid_controller.disable_hid()
    return jsonify(result)

@app.route('/hid/payloads')
def hid_payloads():
    """List available HID payloads"""
    payloads = hid_controller.list_payloads()
    return jsonify(payloads)

@app.route('/hid/execute', methods=['POST'])
def hid_execute():
    """Execute HID payload"""
    try:
        data = request.get_json()
        payload_name = data.get('payload')
        variables = data.get('variables', {})
        
        if not payload_name:
            return jsonify({"error": "Payload name required"}), 400
        
        result = hid_controller.execute_payload(payload_name, variables)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/hid/logs')
def hid_logs():
    """Get HID execution logs"""
    logs = hid_controller.get_execution_log(limit=50)
    return jsonify({"logs": logs})

@app.route('/hid/status')
def hid_status():
    """Get HID system status"""
    status = hid_controller.get_status()
    return jsonify(status)

@app.route('/hid/live-log')
def hid_live_log():
    """Get live execution log"""
    logs = hid_controller.get_live_log(limit=100)
    return jsonify({"logs": logs})

@app.route('/hid/clear-log', methods=['POST'])
def hid_clear_log():
    """Clear live log"""
    hid_controller.clear_live_log()
    return jsonify({"success": True})

@app.route('/scan/set-metadata', methods=['POST'])
def set_metadata():
    """Set scan metadata for file organization"""
    try:
        data = request.get_json()
        device_name = data.get('device_name', 'unknown')
        owner_name = data.get('owner_name', 'unknown')
        scan_type = data.get('scan_type', 'Full_Audit')
        
        set_scan_metadata(device_name, owner_name, scan_type)
        
        return jsonify({
            "success": True,
            "device_name": device_name,
            "owner_name": owner_name,
            "scan_type": scan_type
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/payloads/<filename>')
def serve_payload(filename):
    """Serve dynamically generated .bat payloads"""
    try:
        payload_path = os.path.join('hid', 'payloads', filename)
        if not os.path.exists(payload_path) or not filename.endswith('.bat'):
            return jsonify({"error": "Payload not found"}), 404
            
        with open(payload_path, 'r') as f:
            content = f.read()
            
        network_config = hid_controller.payload_builder.config.get('network', {})
        server_ip = network_config.get('server_ip', '172.16.0.1')
        upload_port = network_config.get('upload_port', 8000)
        
        content = content.replace('{{SERVER_IP}}', str(server_ip))
        content = content.replace('{{UPLOAD_PORT}}', str(upload_port))
        
        return Response(content, mimetype='text/plain')
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Report Generation Routes

@app.route('/report/generate', methods=['POST'])
def generate_audit_report():
    """Generate PDF report from audit files"""
    try:
        data = request.get_json()
        device_name = data.get('device_name', 'unknown')
        owner_name = data.get('owner_name', 'unknown')
        scan_type = data.get('scan_type', 'Full_Audit')
        
        date_str = datetime.now().strftime("%Y-%m-%d")
        safe_owner = owner_name.replace(' ', '_')
        safe_device = device_name.replace(' ', '_')
        safe_type = scan_type.replace(' ', '_')
        
        base_path = os.path.join('uploads', safe_owner, safe_device, date_str, safe_type) + os.path.sep
        
        report_dir = os.path.join('reports', safe_owner, safe_device, date_str, safe_type)
        os.makedirs(report_dir, exist_ok=True)
        output_name = f'{safe_device}_{safe_owner}_{safe_type}_{date_str}_report.pdf'
        report_filepath = os.path.join(report_dir, output_name)
        
        # Log absolute path for debugging
        abs_path = os.path.abspath(base_path)
        print(f"[REPORT] Searching for audit files in: {abs_path}")
        
        # Generate report
        generate_report(base_path, report_filepath)
        
        return jsonify({
            "success": True,
            "report": output_name,
            "report_path": f'/report/download/{safe_owner}/{safe_device}/{date_str}/{safe_type}/{output_name}'
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/report/download/<owner>/<device>/<date_str>/<scan_type>/<filename>')
def download_report(owner, device, date_str, scan_type, filename):
    """Download generated report"""
    try:
        filepath = os.path.join('reports', owner, device, date_str, scan_type, filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        else:
            return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    # Run on port 80 for production (requires sudo on Linux)
    app.run(host='0.0.0.0', port=80, debug=False)
