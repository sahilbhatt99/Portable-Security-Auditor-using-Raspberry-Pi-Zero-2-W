from flask import Flask, render_template, request, jsonify
from datetime import datetime
import json
from hid import HIDController

app = Flask(__name__)

# Initialize HID controller
hid_controller = HIDController()

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

if __name__ == '__main__':
    # Run on port 80 for production (requires sudo on Linux)
    app.run(host='0.0.0.0', port=80, debug=False)
