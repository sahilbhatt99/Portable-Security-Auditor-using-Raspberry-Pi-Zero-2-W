from abc import ABC, abstractmethod

class AuditPlugin(ABC):
    """Base interface for all Modular Audit Plugins"""
    
    @property
    @abstractmethod
    def target_files(self):
        """List of filenames this plugin targets (e.g. ['audit_defender.json'])"""
        pass
        
    @abstractmethod
    def parse(self, filepath):
        """Extracts text structures into summary/findings arrays"""
        pass
        
    @abstractmethod
    def generate_section(self, parsed_data, story, styles):
        """Native reportlab paragraph generation block"""
        pass
