"""
HID Execution System for Portable Security Auditor.
Provides modular USB HID keyboard injection capabilities.
"""

from .hid_controller import HIDController
from .payload_builder import PayloadBuilder
from .executor import HIDExecutor

__all__ = ['HIDController', 'PayloadBuilder', 'HIDExecutor']
__version__ = '1.0.0'
