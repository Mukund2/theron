"""Memory taint tracking for Theron.

Tracks which knowledge in the conversation came from untrusted sources,
and detects when tainted content influences actions.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import uuid4

from ..storage.models import SourceTag, TaintCreate, TaintPropagationCreate


@dataclass
class TaintedMemory:
    """A piece of content marked as tainted (from untrusted source)."""

    taint_id: str
    request_id: str
    content_hash: str
    source_tag: SourceTag
    source_description: str
    tainted_at: datetime
    keywords: list[str]
    content_preview: str
    content_length: int


@dataclass
class TaintPropagation:
    """Record of tainted content influencing an action."""

    propagation_id: str
    source_taint_id: str
    request_id: str
    propagated_to: str  # "tool_call", "assistant_message"
    propagation_type: str  # "direct_reference", "keyword_match", "semantic_similarity"
    confidence: float  # 0.0 to 1.0
    tool_name: Optional[str] = None
    matched_keywords: list[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TaintSummary:
    """Summary of taint status for a request."""

    request_id: str
    total_taints: int
    taint_sources: list[str]
    high_risk_taints: int
    propagation_count: int
    most_influential_taint: Optional[str]


# Keywords to extract from tainted content for tracking
KEYWORD_PATTERNS = [
    r"\b(?:run|execute|sudo|rm|delete|curl|wget|send|post)\b",  # Commands
    r"\b(?:http[s]?://[^\s]+)\b",  # URLs
    r"\b(?:[a-zA-Z_][a-zA-Z0-9_]*)\s*\(",  # Function calls
    r"\b(?:api[_-]?key|token|secret|password)\b",  # Secrets
    r"\b(?:/[a-zA-Z0-9_/.-]+)\b",  # File paths
    r"\b(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})\b",  # Emails
]


class TaintTracker:
    """Tracks tainted memory and propagation."""

    def __init__(self, db=None):
        """Initialize the taint tracker.

        Args:
            db: Optional database instance for persistence.
        """
        self.db = db
        # Track taints per request
        self._taints: dict[str, list[TaintedMemory]] = {}
        # Track propagations per request
        self._propagations: dict[str, list[TaintPropagation]] = {}
        # Compiled keyword patterns
        self._keyword_patterns = [re.compile(p, re.IGNORECASE) for p in KEYWORD_PATTERNS]

    def _hash_content(self, content: str) -> str:
        """Create a hash of content."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _extract_keywords(self, content: str, max_keywords: int = 50) -> list[str]:
        """Extract keywords from content for tracking.

        Args:
            content: Content to extract keywords from
            max_keywords: Maximum number of keywords to extract

        Returns:
            List of extracted keywords
        """
        keywords = set()

        for pattern in self._keyword_patterns:
            matches = pattern.findall(content)
            for match in matches:
                if isinstance(match, str) and len(match) > 2:
                    keywords.add(match.lower().strip())

        # Also extract significant words (longer than 4 chars, not common)
        common_words = {
            "this", "that", "with", "from", "have", "been", "were", "they",
            "their", "would", "could", "should", "about", "which", "there",
            "where", "when", "what", "your", "will", "more", "some", "into",
        }

        words = re.findall(r"\b[a-zA-Z]{5,}\b", content)
        for word in words:
            word_lower = word.lower()
            if word_lower not in common_words:
                keywords.add(word_lower)

        return list(keywords)[:max_keywords]

    def _preview_content(self, content: str, max_len: int = 150) -> str:
        """Create a preview of content."""
        if len(content) <= max_len:
            return content
        return content[:max_len] + "..."

    def mark_tainted(
        self,
        request_id: str,
        content: str,
        source_tag: SourceTag,
        source_description: str,
    ) -> TaintedMemory:
        """Mark content as tainted (from untrusted source).

        Args:
            request_id: Request identifier
            content: The content to mark as tainted
            source_tag: Trust level of the source
            source_description: Human-readable description of the source

        Returns:
            TaintedMemory record
        """
        taint = TaintedMemory(
            taint_id=str(uuid4()),
            request_id=request_id,
            content_hash=self._hash_content(content),
            source_tag=source_tag,
            source_description=source_description,
            tainted_at=datetime.utcnow(),
            keywords=self._extract_keywords(content),
            content_preview=self._preview_content(content),
            content_length=len(content),
        )

        if request_id not in self._taints:
            self._taints[request_id] = []

        self._taints[request_id].append(taint)

        return taint

    def check_taint_influence(
        self,
        request_id: str,
        tool_name: str,
        args: dict,
    ) -> list[TaintPropagation]:
        """Check if a tool call is influenced by tainted memory.

        Args:
            request_id: Request identifier
            tool_name: Name of the tool being called
            args: Arguments to the tool

        Returns:
            List of TaintPropagation records for detected influences
        """
        taints = self._taints.get(request_id, [])
        if not taints:
            return []

        propagations = []
        args_str = json.dumps(args, default=str).lower()
        args_keywords = set(self._extract_keywords(args_str))

        for taint in taints:
            # Check for keyword matches
            matched_keywords = []
            for keyword in taint.keywords:
                if keyword.lower() in args_str:
                    matched_keywords.append(keyword)

            if matched_keywords:
                # Calculate confidence based on number of matches
                confidence = min(len(matched_keywords) / 5.0, 1.0)

                # Boost confidence for exact phrase matches
                if len(matched_keywords) >= 3:
                    confidence = min(confidence + 0.2, 1.0)

                propagation = TaintPropagation(
                    propagation_id=str(uuid4()),
                    source_taint_id=taint.taint_id,
                    request_id=request_id,
                    propagated_to="tool_call",
                    propagation_type="keyword_match",
                    confidence=confidence,
                    tool_name=tool_name,
                    matched_keywords=matched_keywords,
                )
                propagations.append(propagation)

                # Track the propagation
                if request_id not in self._propagations:
                    self._propagations[request_id] = []
                self._propagations[request_id].append(propagation)

            # Check for content hash match (direct copy)
            if taint.content_hash in args_str:
                propagation = TaintPropagation(
                    propagation_id=str(uuid4()),
                    source_taint_id=taint.taint_id,
                    request_id=request_id,
                    propagated_to="tool_call",
                    propagation_type="direct_reference",
                    confidence=1.0,
                    tool_name=tool_name,
                    matched_keywords=["[content_hash]"],
                )
                propagations.append(propagation)

                if request_id not in self._propagations:
                    self._propagations[request_id] = []
                self._propagations[request_id].append(propagation)

        return propagations

    def get_taint_summary(self, request_id: str) -> TaintSummary:
        """Get summary of taint status for a request.

        Args:
            request_id: Request identifier

        Returns:
            TaintSummary object
        """
        taints = self._taints.get(request_id, [])
        propagations = self._propagations.get(request_id, [])

        # Count high-risk taints (from CONTENT_READ or TOOL_RESULT)
        high_risk_taints = sum(
            1 for t in taints
            if t.source_tag in (SourceTag.CONTENT_READ, SourceTag.TOOL_RESULT)
        )

        # Find most influential taint (most propagations)
        taint_propagation_counts: dict[str, int] = {}
        for prop in propagations:
            taint_propagation_counts[prop.source_taint_id] = (
                taint_propagation_counts.get(prop.source_taint_id, 0) + 1
            )

        most_influential = None
        if taint_propagation_counts:
            most_influential = max(
                taint_propagation_counts.keys(),
                key=lambda k: taint_propagation_counts[k],
            )

        return TaintSummary(
            request_id=request_id,
            total_taints=len(taints),
            taint_sources=list({t.source_description for t in taints}),
            high_risk_taints=high_risk_taints,
            propagation_count=len(propagations),
            most_influential_taint=most_influential,
        )

    def get_taints_for_request(self, request_id: str) -> list[TaintedMemory]:
        """Get all taints for a request.

        Args:
            request_id: Request identifier

        Returns:
            List of TaintedMemory records
        """
        return self._taints.get(request_id, [])

    def get_propagations_for_request(self, request_id: str) -> list[TaintPropagation]:
        """Get all propagations for a request.

        Args:
            request_id: Request identifier

        Returns:
            List of TaintPropagation records
        """
        return self._propagations.get(request_id, [])

    def get_taint_influence_score(self, request_id: str) -> float:
        """Calculate overall taint influence score for a request.

        Higher scores indicate more influence from tainted content.

        Args:
            request_id: Request identifier

        Returns:
            Influence score from 0.0 to 1.0
        """
        taints = self._taints.get(request_id, [])
        propagations = self._propagations.get(request_id, [])

        if not taints:
            return 0.0

        # Base score from having taints
        base_score = min(len(taints) / 5.0, 0.3)

        # Propagation score
        if propagations:
            avg_confidence = sum(p.confidence for p in propagations) / len(propagations)
            propagation_score = avg_confidence * 0.5  # Up to 0.5 from propagations
        else:
            propagation_score = 0.0

        # High-risk taint bonus
        high_risk_count = sum(
            1 for t in taints
            if t.source_tag in (SourceTag.CONTENT_READ, SourceTag.TOOL_RESULT)
        )
        high_risk_score = min(high_risk_count / 3.0, 0.2)

        return min(base_score + propagation_score + high_risk_score, 1.0)

    def has_high_taint_influence(self, request_id: str, threshold: float = 0.5) -> bool:
        """Check if request has high taint influence.

        Args:
            request_id: Request identifier
            threshold: Influence threshold (default 0.5)

        Returns:
            True if influence score exceeds threshold
        """
        return self.get_taint_influence_score(request_id) >= threshold

    def clear_request(self, request_id: str) -> None:
        """Clear taint data for a request.

        Args:
            request_id: Request to clear
        """
        self._taints.pop(request_id, None)
        self._propagations.pop(request_id, None)

    async def persist_taints(self, request_id: str) -> None:
        """Persist taints and propagations to database.

        Args:
            request_id: Request to persist
        """
        if not self.db:
            return

        taints = self._taints.get(request_id, [])
        for taint in taints:
            taint_create = TaintCreate(
                taint_id=taint.taint_id,
                request_id=taint.request_id,
                content_hash=taint.content_hash,
                source_tag=taint.source_tag.value if isinstance(taint.source_tag, SourceTag) else taint.source_tag,
                source_description=taint.source_description,
                keywords=taint.keywords,
                content_preview=taint.content_preview,
            )
            await self.db.create_taint(taint_create)

        propagations = self._propagations.get(request_id, [])
        for prop in propagations:
            prop_create = TaintPropagationCreate(
                propagation_id=prop.propagation_id,
                source_taint_id=prop.source_taint_id,
                request_id=prop.request_id,
                propagated_to=prop.propagated_to,
                propagation_type=prop.propagation_type,
                confidence=prop.confidence,
                tool_name=prop.tool_name,
            )
            await self.db.create_taint_propagation(prop_create)

    def get_taint_report(self, request_id: str) -> dict:
        """Generate a detailed taint report for a request.

        Args:
            request_id: Request identifier

        Returns:
            Detailed taint report dictionary
        """
        taints = self._taints.get(request_id, [])
        propagations = self._propagations.get(request_id, [])
        summary = self.get_taint_summary(request_id)

        return {
            "summary": {
                "total_taints": summary.total_taints,
                "taint_sources": summary.taint_sources,
                "high_risk_taints": summary.high_risk_taints,
                "propagation_count": summary.propagation_count,
                "influence_score": self.get_taint_influence_score(request_id),
            },
            "taints": [
                {
                    "taint_id": t.taint_id,
                    "source_tag": t.source_tag.value if isinstance(t.source_tag, SourceTag) else t.source_tag,
                    "source_description": t.source_description,
                    "keyword_count": len(t.keywords),
                    "content_preview": t.content_preview,
                    "content_length": t.content_length,
                }
                for t in taints
            ],
            "propagations": [
                {
                    "propagation_id": p.propagation_id,
                    "source_taint_id": p.source_taint_id,
                    "propagation_type": p.propagation_type,
                    "confidence": p.confidence,
                    "tool_name": p.tool_name,
                    "matched_keywords": p.matched_keywords[:10],  # Limit for display
                }
                for p in propagations
            ],
        }
