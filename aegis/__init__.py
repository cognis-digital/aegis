"""
AEGIS — AI Agent Permission & Access Auditor
Part of the Cognis Neural Suite by Cognis Digital
https://cognis.digital · MIT License
"""
from aegis.models import Agent, Tool, Finding, ScanResult, ReachProfile
from aegis.core import scan
from aegis.scoring import score, detect_lethal_trifecta, RISK_LEVELS

__version__ = "0.1.0"
__author__ = "Cognis Digital"
__license__ = "MIT"

__all__ = [
    "scan",
    "score",
    "detect_lethal_trifecta",
    "Agent",
    "Tool",
    "Finding",
    "ScanResult",
    "ReachProfile",
    "RISK_LEVELS",
    "__version__",
]
