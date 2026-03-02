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
        self.cooldown_seconds = 10  # Prevent rapid re-execution
    
    def enable_hid(self):
        """Enable HID injection system"""
        self.enabled = True
        logger.info("HID system enabled")
        return {"status": "enabled", "timestamp": datetime.now().isoformat()}
    
    def disable_hid(self):
        """Disable HID injection system"""
        self.enabled = False
        logger.info("HID system disabled")
        return {"status": "disabled", "timestamp": datetime.now().isoformat()}
    
    def is_enabled(self):
        """Check if HID system is enabled"""
        return self.enabled
    
    def _check_cooldown(self, payload_name):
        """
        Check if payload is in cooldown period.
        
        Args:
            payload_name: Name of payload to check
        
        Returns:
            True if cooldown active, False otherwise
        """
        if payload_name in self.last_execution:
            last_time = self.last_execution[payload_name]
            elapsed = (datetime.now() - last_time).total_seconds()
            if elapsed < self.cooldown_seconds:
                return True
        return False
    
    def _log_execution(self, payload_name, status, error=None):
        """Log payload execution event"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'payload': payload_name,
            'status': status,
            'error': error
        }
        self.execution_log.append(log_entry)
        logger.info(f"Execution logged: {payload_name} - {status}")
        
        # Keep only last 100 entries
        if len(self.execution_log) > 100:
            self.execution_log.pop(0)
    
    def execute_payload(self, payload_name, variables=None):
        """
        Execute a payload by name.
        
        Args:
            payload_name: Name of registered payload
            variables: Optional dict of variables for substitution
        
        Returns:
            Dict with execution result
        """
        # Check if enabled
        if not self.enabled:
            error = "HID system is disabled"
            logger.warning(f"Execution blocked: {error}")
            return {"success": False, "error": error}
        
        # Check cooldown
        if self._check_cooldown(payload_name):
            error = f"Payload '{payload_name}' in cooldown period"
            logger.warning(f"Execution blocked: {error}")
            return {"success": False, "error": error}
        
        try:
            # Get payload commands
            commands = self.payload_builder.get_payload(payload_name, variables)
            
            logger.info(f"Executing payload: {payload_name}")
            
            # Execute each command
            for cmd in commands:
                action = cmd.get('action')
                
                if action == 'type':
                    self.executor.type_string(cmd['text'])
                
                elif action == 'key':
                    self.executor.press_key(cmd['name'])
                
                elif action == 'combo':
                    keys = cmd['keys']
                    modifiers = keys[:-1]
                    key = keys[-1]
                    self.executor.key_combo(modifiers, key)
                
                elif action == 'delay':
                    self.executor.delay(cmd['ms'])
                
                else:
                    logger.warning(f"Unknown action: {action}")
            
            # Update last execution time
            self.last_execution[payload_name] = datetime.now()
            
            # Log success
            self._log_execution(payload_name, 'success')
            
            return {
                "success": True,
                "payload": payload_name,
                "timestamp": datetime.now().isoformat()
            }
        
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Execution failed: {payload_name} - {error_msg}")
            self._log_execution(payload_name, 'failed', error_msg)
            
            return {
                "success": False,
                "error": error_msg,
                "payload": payload_name
            }
    
    def get_execution_log(self, limit=50):
        """
        Get recent execution log entries.
        
        Args:
            limit: Maximum number of entries to return
        
        Returns:
            List of log entries
        """
        return self.execution_log[-limit:]
    
    def list_payloads(self):
        """List all available payloads"""
        return self.payload_builder.list_payloads()
    
    def get_status(self):
        """Get current HID system status"""
        return {
            "enabled": self.enabled,
            "available_payloads": len(self.payload_builder.payloads),
            "executions_logged": len(self.execution_log),
            "cooldown_seconds": self.cooldown_seconds
        }
