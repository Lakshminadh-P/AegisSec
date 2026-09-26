"""
Base Scanner Class

All security scanners inherit from this base class.
This ensures a consistent interface across different tools.

Design Pattern: Template Method
- is_available() checks if the tool is installed
- scan() runs the tool and returns normalized results
- parse_output() converts tool-specific output to our common format
"""
import subprocess
import shutil
from abc import ABC, abstractmethod
from typing import List, Optional


class BaseScanner(ABC):
    """Abstract base class for security scanners."""
    
    # Override these in subclasses
    name: str = "base"
    display_name: str = "Base Scanner"
    scan_type: str = "UNKNOWN"
    tool_command: str = ""
    description: str = ""
    
    def is_available(self) -> bool:
        """Check if the security tool is installed on the system.
        
        Uses shutil.which() to find the tool in PATH.
        This is how we gracefully handle missing tools.
        """
        if not self.tool_command:
            return False
        return shutil.which(self.tool_command) is not None
    
    def run_command(self, command: list, timeout: int = 300) -> Optional[str]:
        """Safely execute a subprocess command.
        
        Security considerations:
        - Uses a list (not shell=True) to prevent command injection
        - Sets a timeout to prevent hanging
        - Captures output for parsing
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,  # Security: never use shell=True with user input
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return None
        except FileNotFoundError:
            return None
        except Exception:
            return None
    
    @abstractmethod
    def scan(self, target: str) -> List[dict]:
        """Run the scan and return normalized vulnerability findings.
        
        Each finding should be a dict matching VulnerabilityCreate schema:
        {
            "title": str,
            "severity": str,  # CRITICAL, HIGH, MEDIUM, LOW
            "source": str,    # Scanner name
            "component": str,
            "description": str,
            "cve": str or None,
            "status": "OPEN",
            "risk_score": float,
        }
        """
        pass
    
    @abstractmethod
    def parse_output(self, raw_output: str) -> List[dict]:
        """Parse tool-specific output into normalized format."""
        pass
