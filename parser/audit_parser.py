"""
Re-Architected Audit file parser using active Plugin Module boundaries mapping specific file types.
"""
import os
import json
from datetime import datetime

from parser.plugins.defender_plugin import DefenderPlugin
from parser.plugins.firewall_plugin import FirewallPlugin
from parser.plugins.hardware_plugin import HardwarePlugin
from parser.plugins.net_users_plugin import NetUsersPlugin
from parser.plugins.sysinfo_plugin import SysinfoPlugin
from parser.plugins.policy_plugin import PolicyPlugin
from parser.plugins.registry_plugin import RegistryPlugin

class AuditParser:
    """Parses Windows audit output files using Plugin Architecture"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'hostname': 'Unknown',
            'findings': [],
            'summary': {}
        }
        # Initialize plugins
        self.plugins = [
            DefenderPlugin(),
            FirewallPlugin(),
            HardwarePlugin(),
            NetUsersPlugin(),
            SysinfoPlugin(),
            PolicyPlugin(),
            RegistryPlugin()
        ]
        
    def analyze_all(self, upload_dir):
        if not os.path.exists(upload_dir):
            return self.results
            
        plugin_cache = {}
            
        for filename in os.listdir(upload_dir):
            filepath = os.path.join(upload_dir, filename)
            if not os.path.isfile(filepath):
                continue
                
            # Find supporting plugin
            for plugin in self.plugins:
                if any(t in filename for t in plugin.target_files) or filename in plugin.target_files:
                    try:
                        parsed_data = plugin.parse(filepath)
                        
                        # Populate global vulnerabilities into array
                        if 'vulnerabilities' in parsed_data:
                            self.results['findings'].extend(parsed_data['vulnerabilities'])
                            
                        # Extract sysinfo immediately
                        if isinstance(plugin, SysinfoPlugin) and 'hostname' in parsed_data:
                            self.results['hostname'] = parsed_data['hostname']
                            
                        # Store raw data bound to plugin name structurally for reportgen
                        plugin_cache_name = plugin.__class__.__name__
                        if plugin_cache_name not in plugin_cache:
                            plugin_cache[plugin_cache_name] = []
                        plugin_cache[plugin_cache_name].append(parsed_data)
                    except Exception as e:
                        print(f"Plugin Parser Failure on {filename} via {plugin.__name__}: {e}")
                        
        self.results['summary']['plugin_cache'] = plugin_cache
        return self.results

