"""Advanced intelligence modules for Theron.

This package contains:
- Causal chain tracking
- Exfiltration detection
- Loop hijack detection
- Honeypot injection
- Memory taint tracking
- Intelligence manager (coordinates all modules)
"""

from .causal import CausalTracker, CausalNode, CausalChain
from .exfiltration import ExfiltrationDetector, ExfiltrationAlert, SensitiveAccess
from .hijack import HijackDetector, HijackAlert, InferredIntent
from .honeypot import HoneypotManager, Honeypot, HoneypotAlert
from .taint import TaintTracker, TaintedMemory, TaintPropagation
from .manager import IntelligenceManager, get_intelligence_manager, reset_intelligence_manager

__all__ = [
    "CausalTracker",
    "CausalNode",
    "CausalChain",
    "ExfiltrationDetector",
    "ExfiltrationAlert",
    "SensitiveAccess",
    "HijackDetector",
    "HijackAlert",
    "InferredIntent",
    "HoneypotManager",
    "Honeypot",
    "HoneypotAlert",
    "TaintTracker",
    "TaintedMemory",
    "TaintPropagation",
    "IntelligenceManager",
    "get_intelligence_manager",
    "reset_intelligence_manager",
]
