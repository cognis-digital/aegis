"""AEGIS - AI Agent Permission & Access Auditor.

Surfaces the "lethal trifecta" of agent risk:
  1. CREDENTIALS  - access to secrets / sensitive data
  2. INJECTION    - exposure to untrusted / attacker-controllable input
  3. REACH        - ability to exfiltrate or act on the outside world

An agent with all three is one prompt injection away from a breach.
"""

from .core import (
    Finding,
    AuditReport,
    audit_manifest,
    audit_file,
    load_manifest,
    classify_capability,
    CAPABILITY_AXES,
)

TOOL_NAME = "aegis"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "AuditReport",
    "audit_manifest",
    "audit_file",
    "load_manifest",
    "classify_capability",
    "CAPABILITY_AXES",
    "TOOL_NAME",
    "TOOL_VERSION",
]
