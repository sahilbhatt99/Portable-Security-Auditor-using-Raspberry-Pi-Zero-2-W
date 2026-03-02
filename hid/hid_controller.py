"""
HID Controller - High-level interface for HID payload execution.
Manages execution state, logging, and safety mechanisms.
"""

import time
import logging
from datetime import datetime, timedelta
from .executor import HIDExecutor
from .payload_builder import PayloadBuilder


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('HIDController')


class HIDController:
    """High-level HID injection controller"""
    
    def __init__(self):
        self.executor = HIDExecutor()
        self.payload_builder = PayloadBuilder()
        self.enabled = False
        self.execution_log = []
        self.last_execution = {}
        self.cooldown_seconds = 5
        self.live_log = []
        self.current_execution = None
    
    def enable_hid(self):
        """Enable HID injection system"""
        self.enabled = True
        self._log_live("HID system enabled")
        return {"status": "enabled", "timestamp": datetime.now().isoformat()}
    
    def disable_hid(self):
        """Disable HID injection system"""
        self.enabled = False
        self._log_live("HID system disabled")
        return {"status": "disabled", "timestamp": datetime.now().isoformat()}
    
    def is_enabled(self):
        """Check if HID system is enabled"""
        return self.enabled
    
    def _check_cooldown(self, payload_name):
        """Check if payload is in cooldown period"""
        if payload_name in self.last_execution:
            last_time = self.last_execution[payload_name]
            elapsed = (datetime.now() - last_time).total_seconds()
            if elapsed < self.cooldown_seconds:
                return True
        return False
    
    def _log_live(self, message, level='info'):
        """Add message to live log"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'level': level
        }
        self.live_log.append(entry)
        if len(self.live_log) > 200:
            self.live_log.pop(0)
        logger.info(message)
    
    def _log_execution(self, payload_name, status, error=None):
        """Log payload execution event"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'payload': payload_name,
            'status': status,
            'error': error
        }
        self.execution_log.append(log_entry)
        if len(self.execution_log) > 100:
            self.execution_log.pop(0)
    
    def execute_payload(self, payload_name, variables=None):
        """Execute a payload by name"""
        if not self.enabled:
            error = "HID system is disabled"
            self._log_live(f"Execution blocked: {error}", 'error')
            return {"success": False, "error": error}
        
        if self._check_cooldown(payload_name):
            error = f"Payload '{payload_name}' in cooldown period"
            self._log_live(f"Execution blocked: {error}", 'warning')
            return {"success": False, "error": error}
        
        try:
            commands = self.payload_builder.get_payload(payload_name, variables)
            
            self.current_execution = payload_name
            self._log_live(f"Starting execution: {payload_name}")
            self._log_live(f"Total commands: {len(commands)}")
            
            for i, cmd in enumerate(commands, 1):
                action = cmd.get('action')
                
                if action == 'type':
                    text = cmd['text'][:50] + '...' if len(cmd['text']) > 50 else cmd['text']
                    self._log_live(f"[{i}/{len(commands)}] Typing: {text}")
                    self.executor.type_string(cmd['text'])
                
                elif action == 'key':
                    self._log_live(f"[{i}/{len(commands)}] Pressing key: {cmd['name']}")
                    self.executor.press_key(cmd['name'])
                
                elif action == 'combo':
                    keys = cmd['keys']
                    combo_str = '+'.join(keys)
                    self._log_live(f"[{i}/{len(commands)}] Key combo: {combo_str}")
                    modifiers = keys[:-1]
                    key = keys[-1]
                    self.executor.key_combo(modifiers, key)
                
                elif action == 'delay':
                    self._log_live(f"[{i}/{len(commands)}] Waiting {cmd['ms']}ms")
                    self.executor.delay(cmd['ms'])
                
                else:
                    self._log_live(f"Unknown action: {action}", 'warning')
            
            self.last_execution[payload_name] = datetime.now()
            self._log_execution(payload_name, 'success')
            self._log_live(f"✓ Execution completed: {payload_name}", 'success')
            self.current_execution = None
            
            return {
                "success": True,
                "payload": payload_name,
                "timestamp": datetime.now().isoformat()
            }
        
        except Exception as e:
            error_msg = str(e)
            self._log_live(f"✗ Execution failed: {error_msg}", 'error')
            self._log_execution(payload_name, 'failed', error_msg)
            self.current_execution = None
            
            return {
                "success": False,
                "error": error_msg,
                "payload": payload_name
            }
    
    def get_execution_log(self, limit=50):
        """Get recent execution log entries"""
        return self.execution_log[-limit:]
    
    def get_live_log(self, limit=50):
        """Get recent live log entries"""
        return self.live_log[-limit:]
    
    def clear_live_log(self):
        """Clear live log"""
        self.live_log = []
    
    def list_payloads(self):
        """List all available payloads"""
        return self.payload_builder.list_payloads()
    
    def get_status(self):
        """Get current HID system status"""
        return {
            "enabled": self.enabled,
            "available_payloads": len(self.payload_builder.payloads),
            "executions_logged": len(self.execution_log),
            "cooldown_seconds": self.cooldown_seconds,
            "current_execution": self.current_execution,
            "live_log_count": len(self.live_log)
        }
