"""Intelligence manager for Theron.

Coordinates all intelligence modules and provides a unified interface
for the proxy handlers to use.
"""

from typing import Optional, Any
from datetime import datetime

from ..storage.models import SourceTag
from .causal import CausalTracker
from .exfiltration import ExfiltrationDetector
from .hijack import HijackDetector
from .honeypot import HoneypotManager
from .taint import TaintTracker
from ..learning.baseline import BaselineManager
from ..learning.anomaly import AnomalyScorer


class IntelligenceManager:
    """Manages all intelligence modules for enhanced security analysis."""

    def __init__(self, db=None, enabled: bool = True):
        """Initialize the intelligence manager.

        Args:
            db: Optional database instance for persistence.
            enabled: Whether intelligence features are enabled.
        """
        self.db = db
        self.enabled = enabled

        # Initialize all trackers
        self.causal_tracker = CausalTracker(db)
        self.exfil_detector = ExfiltrationDetector(db)
        self.hijack_detector = HijackDetector(db)
        self.honeypot_mgr = HoneypotManager(db, injection_rate=0.30)
        self.taint_tracker = TaintTracker(db)
        self.baseline_mgr = BaselineManager(db, min_requests_for_baseline=25)
        self.anomaly_scorer = AnomalyScorer(self.baseline_mgr)

    def start_request(
        self,
        request_id: str,
        conversation: list[dict],
        agent_id: Optional[str] = None,
    ) -> dict:
        """Start tracking a new request.

        Args:
            request_id: Unique request identifier
            conversation: List of conversation messages
            agent_id: Optional agent identifier

        Returns:
            Initial analysis context
        """
        if not self.enabled:
            return {"enabled": False}

        # Find first user message for causal chain root
        user_message = ""
        for msg in conversation:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, list):
                    content = " ".join(
                        c.get("text", "") for c in content if isinstance(c, dict)
                    )
                user_message = content
                break

        # Start causal chain
        self.causal_tracker.start_chain(request_id, user_message)

        # Infer intent for hijack detection
        self.hijack_detector.infer_intent(request_id, conversation)

        return {
            "enabled": True,
            "request_id": request_id,
            "intent": self.hijack_detector.get_intent(request_id),
        }

    def track_content(
        self,
        request_id: str,
        content: str,
        source_tag: SourceTag,
        source_description: str,
        threat_score: float = 0.0,
    ) -> dict:
        """Track content being read/processed.

        Args:
            request_id: Request identifier
            content: The content being processed
            source_tag: Trust level of the content
            source_description: Description of the source
            threat_score: Threat score from injection detection

        Returns:
            Tracking results
        """
        if not self.enabled:
            return {}

        results = {}

        # Add to causal chain
        self.causal_tracker.add_content_node(
            request_id, content, source_tag, source_description, threat_score
        )

        # Track for exfiltration detection
        sensitive = self.exfil_detector.track_content_access(
            request_id, content, source_description
        )
        if sensitive:
            results["sensitive_data_detected"] = True
            results["sensitive_types"] = [m.data_type for m in sensitive.matches]

        # Mark as tainted if untrusted
        if source_tag in (SourceTag.CONTENT_READ, SourceTag.TOOL_RESULT):
            taint = self.taint_tracker.mark_tainted(
                request_id, content, source_tag, source_description
            )
            results["tainted"] = True
            results["taint_id"] = taint.taint_id

        return results

    def track_tool_result(
        self,
        request_id: str,
        tool_name: str,
        result: str,
        threat_score: float = 0.0,
    ) -> dict:
        """Track a tool execution result.

        Args:
            request_id: Request identifier
            tool_name: Name of the tool
            result: Tool output
            threat_score: Threat score from detection

        Returns:
            Tracking results including any honeypot injections
        """
        if not self.enabled:
            return {"modified_result": result}

        # Add to causal chain
        self.causal_tracker.add_tool_result_node(
            request_id, tool_name, result, SourceTag.TOOL_RESULT, threat_score
        )

        # Try to inject honeypots into file read results
        modified_result = result
        honeypots = []

        if tool_name in ("read_file", "cat", "file_read", "get_file_contents"):
            modified_result, honeypots = self.honeypot_mgr.inject_honeypots(
                result, request_id, source_type="tool_result"
            )

        return {
            "modified_result": modified_result,
            "honeypots_injected": len(honeypots),
        }

    def evaluate_tool_call(
        self,
        request_id: str,
        tool_name: str,
        args: dict,
        risk_tier: int,
        agent_id: Optional[str] = None,
    ) -> dict:
        """Evaluate a tool call with all intelligence signals.

        Args:
            request_id: Request identifier
            tool_name: Name of the tool
            args: Tool arguments
            risk_tier: Risk tier of the tool
            agent_id: Optional agent identifier

        Returns:
            Intelligence evaluation results
        """
        if not self.enabled:
            return {
                "block_reasons": [],
                "risk_score": 0.0,
            }

        results = {
            "block_reasons": [],
            "alerts": [],
            "risk_factors": {},
        }

        # 1. Check honeypot use
        honeypot_alert = self.honeypot_mgr.check_for_honeypot_use(tool_name, args)
        if honeypot_alert:
            results["block_reasons"].append("honeypot_triggered")
            results["alerts"].append({
                "type": "honeypot",
                "alert_id": honeypot_alert.alert_id,
                "severity": "critical",
            })
            results["honeypot_alert"] = honeypot_alert

        # 2. Check exfiltration
        exfil_alert = self.exfil_detector.check_outbound_action(request_id, tool_name, args)
        if exfil_alert:
            results["block_reasons"].append("exfiltration_detected")
            results["alerts"].append({
                "type": "exfiltration",
                "alert_id": exfil_alert.alert_id,
                "severity": exfil_alert.severity,
            })
            results["exfil_alert"] = exfil_alert

        # 3. Check hijack / intent drift
        hijack_alert = self.hijack_detector.check_tool_alignment(request_id, tool_name, args)
        if hijack_alert:
            results["alerts"].append({
                "type": "hijack",
                "alert_id": hijack_alert.alert_id,
                "severity": hijack_alert.severity,
                "drift_score": hijack_alert.drift_score,
            })
            results["risk_factors"]["hijack_drift"] = hijack_alert.drift_score
            results["hijack_alert"] = hijack_alert

        # 4. Check anomaly
        if agent_id:
            anomaly = self.anomaly_scorer.score_action(
                agent_id, tool_name, risk_tier, datetime.utcnow().hour
            )
            results["risk_factors"]["anomaly_score"] = anomaly.score
            results["anomaly"] = anomaly

        # 5. Check taint influence
        propagations = self.taint_tracker.check_taint_influence(request_id, tool_name, args)
        results["risk_factors"]["taint_influence"] = len(propagations)
        if propagations:
            results["taint_propagations"] = propagations

        # 6. Get causal chain risk
        chain = self.causal_tracker.get_chain(request_id)
        if chain:
            results["risk_factors"]["chain_risk"] = chain.risk_score
            results["chain_summary"] = self.causal_tracker.get_chain_summary(request_id)

        # Add tool call to causal chain
        self.causal_tracker.add_tool_call_node(
            request_id, tool_name, args, risk_tier
        )

        # Calculate composite risk
        results["composite_risk"] = self._calculate_composite_risk(results["risk_factors"], risk_tier)

        return results

    def _calculate_composite_risk(self, factors: dict, base_tier: int) -> float:
        """Calculate composite risk from factors.

        Args:
            factors: Risk factor dictionary
            base_tier: Base risk tier

        Returns:
            Composite risk score (0.0 to 1.0)
        """
        weights = {
            "chain_risk": 0.20,
            "anomaly_score": 0.25,
            "hijack_drift": 0.25,
            "taint_influence": 0.15,
            "base_tier": 0.15,
        }

        normalized = {
            "chain_risk": factors.get("chain_risk", 0),
            "anomaly_score": factors.get("anomaly_score", 0),
            "hijack_drift": factors.get("hijack_drift", 0),
            "taint_influence": min(factors.get("taint_influence", 0) / 5.0, 1.0),
            "base_tier": (base_tier - 1) / 3.0,
        }

        return sum(normalized[k] * weights[k] for k in weights)

    def update_baseline(
        self,
        agent_id: str,
        tool_name: Optional[str] = None,
        risk_tier: Optional[int] = None,
        threat_score: float = 0.0,
        source_tag: Optional[str] = None,
    ) -> None:
        """Update agent behavioral baseline.

        Args:
            agent_id: Agent identifier
            tool_name: Tool used
            risk_tier: Risk tier
            threat_score: Threat score
            source_tag: Source tag
        """
        if not self.enabled or not agent_id:
            return

        self.baseline_mgr.update_profile(
            agent_id, tool_name, risk_tier, threat_score, source_tag
        )

    def learn_from_approval(
        self,
        agent_id: str,
        tool_name: str,
        approved: bool,
    ) -> None:
        """Learn from user's sandbox approval/rejection.

        Args:
            agent_id: Agent identifier
            tool_name: Tool that was sandboxed
            approved: Whether user approved
        """
        if not self.enabled or not agent_id:
            return

        self.baseline_mgr.learn_from_approval(agent_id, tool_name, approved)

    def end_request(self, request_id: str, persist: bool = True) -> dict:
        """End tracking for a request.

        Args:
            request_id: Request to end
            persist: Whether to persist data to database

        Returns:
            Final summary
        """
        if not self.enabled:
            return {}

        summary = {
            "causal_chain": self.causal_tracker.get_chain_summary(request_id),
            "taint_report": self.taint_tracker.get_taint_report(request_id),
            "exfiltration": self.exfil_detector.get_sensitive_summary(request_id),
            "hijack": self.hijack_detector.get_drift_summary(request_id),
        }

        # Clear in-memory data
        self.causal_tracker.clear_chain(request_id)
        self.exfil_detector.clear_request(request_id)
        self.taint_tracker.clear_request(request_id)
        self.hijack_detector.clear_request(request_id)

        return summary

    def get_intelligence_summary(self) -> dict:
        """Get overall intelligence summary.

        Returns:
            Summary of all intelligence data
        """
        return {
            "honeypots": self.honeypot_mgr.get_honeypot_stats(),
            "profiles": len(self.baseline_mgr.get_all_profiles()),
            "enabled": self.enabled,
        }


# Global intelligence manager instance
_intelligence_manager: Optional[IntelligenceManager] = None


def get_intelligence_manager(db=None) -> IntelligenceManager:
    """Get the global intelligence manager instance.

    Args:
        db: Optional database instance

    Returns:
        IntelligenceManager instance
    """
    global _intelligence_manager
    if _intelligence_manager is None:
        _intelligence_manager = IntelligenceManager(db, enabled=True)
    return _intelligence_manager


def reset_intelligence_manager() -> None:
    """Reset the global intelligence manager."""
    global _intelligence_manager
    _intelligence_manager = None
