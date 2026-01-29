"""Prompt injection detection for Theron.

Scans content for embedded instructions that could hijack the AI.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..config import TheronConfig, get_config
from ..patterns import CATEGORY_WEIGHTS, INJECTION_PATTERNS


@dataclass
class PatternMatch:
    """A detected pattern match."""

    category: str
    pattern: str
    matched_text: str
    weight: int
    position: int


@dataclass
class ThreatAnalysis:
    """Result of threat analysis on content."""

    threat_score: int  # 0-100
    injection_detected: bool
    pattern_matches: list[PatternMatch] = field(default_factory=list)
    structural_signals: dict[str, Any] = field(default_factory=dict)
    source_multiplier: float = 1.0


class InjectionDetector:
    """Detects prompt injection attacks in content."""

    def __init__(self, config: Optional[TheronConfig] = None):
        """Initialize the detector.

        Args:
            config: Optional TheronConfig. If not provided, loads from file.
        """
        self.config = config or get_config()
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficient matching."""
        detection_config = self.config.detection

        for category, patterns in INJECTION_PATTERNS.items():
            # Check if category is enabled
            if detection_config.categories.get(category, True):
                self._compiled_patterns[category] = [
                    re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns
                ]

        # Add custom patterns
        for custom in detection_config.custom_patterns:
            pattern = custom.get("pattern")
            if pattern:
                category = custom.get("category", "custom")
                if category not in self._compiled_patterns:
                    self._compiled_patterns[category] = []
                try:
                    self._compiled_patterns[category].append(
                        re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    )
                except re.error:
                    pass  # Skip invalid patterns

    def analyze(self, content: str, source_tag: Optional[str] = None) -> ThreatAnalysis:
        """Analyze content for prompt injection threats.

        Args:
            content: The content to analyze
            source_tag: Optional source tag (affects scoring)

        Returns:
            ThreatAnalysis with threat score and details
        """
        matches: list[PatternMatch] = []
        score = 0

        # Pattern matching
        for category, patterns in self._compiled_patterns.items():
            weight = CATEGORY_WEIGHTS.get(category, 10)

            # Adjust weight for custom patterns
            if category == "custom":
                for custom in self.config.detection.custom_patterns:
                    if custom.get("weight"):
                        weight = custom["weight"]

            for pattern in patterns:
                for match in pattern.finditer(content):
                    matches.append(
                        PatternMatch(
                            category=category,
                            pattern=pattern.pattern,
                            matched_text=match.group(),
                            weight=weight,
                            position=match.start(),
                        )
                    )
                    score += weight

        # Structural analysis
        structural = self._analyze_structure(content)
        score += structural.get("score_adjustment", 0)

        # Source multiplier (untrusted content is riskier)
        source_multiplier = 1.0
        if source_tag == "CONTENT_READ":
            source_multiplier = 1.5
        elif source_tag == "TOOL_RESULT":
            source_multiplier = 1.3

        final_score = int(min(score * source_multiplier, 100))

        return ThreatAnalysis(
            threat_score=final_score,
            injection_detected=final_score >= self.config.detection.injection_threshold,
            pattern_matches=matches,
            structural_signals=structural,
            source_multiplier=source_multiplier,
        )

    def _analyze_structure(self, content: str) -> dict[str, Any]:
        """Analyze structural signals in content.

        Returns dict with structural findings and score adjustment.
        """
        signals: dict[str, Any] = {}
        score_adjustment = 0

        # Count imperative sentences (commands)
        imperatives = self._count_imperatives(content)
        signals["imperative_count"] = imperatives
        if imperatives > 3:
            score_adjustment += 15
            signals["high_imperative_density"] = True

        # Check for delimiter characters
        delimiters = self._has_delimiter_chars(content)
        signals["has_delimiters"] = delimiters
        if delimiters:
            score_adjustment += 20

        # Calculate instruction density
        density = self._instruction_density(content)
        signals["instruction_density"] = density
        if density > 0.3:
            score_adjustment += 25

        # Check for hidden content patterns
        if self._has_hidden_content(content):
            signals["has_hidden_content"] = True
            score_adjustment += 30

        # Check for encoding attempts
        if self._has_encoding_attempt(content):
            signals["has_encoding"] = True
            score_adjustment += 25

        signals["score_adjustment"] = score_adjustment
        return signals

    def _count_imperatives(self, content: str) -> int:
        """Count imperative (command) sentences."""
        # Simple heuristic: sentences starting with verbs
        imperative_starters = [
            r"^(?:do|run|execute|send|delete|create|make|get|set|put|post|call|invoke|use|ignore|forget|disregard|pretend|act|become|switch|enable|disable|override|bypass)\b",
        ]

        count = 0
        sentences = re.split(r"[.!?\n]", content)
        for sentence in sentences:
            sentence = sentence.strip()
            for pattern in imperative_starters:
                if re.match(pattern, sentence, re.IGNORECASE):
                    count += 1
                    break
        return count

    def _has_delimiter_chars(self, content: str) -> bool:
        """Check for suspicious delimiter characters."""
        delimiter_patterns = [
            r"</?[a-zA-Z_]+>",  # XML-like tags
            r"\[/?[A-Z]+\]",  # Bracket tags
            r"```\s*\w+",  # Code blocks with language
            r"<\|[^|]+\|>",  # Special tokens
        ]
        for pattern in delimiter_patterns:
            if re.search(pattern, content):
                return True
        return False

    def _instruction_density(self, content: str) -> float:
        """Calculate the density of instruction-like content."""
        if not content:
            return 0.0

        instruction_patterns = [
            r"\b(?:must|should|need to|have to|required to)\b",
            r"\b(?:always|never|don't|do not|stop|start)\b",
            r"\b(?:important|critical|urgent|immediately)\b",
        ]

        instruction_words = 0
        for pattern in instruction_patterns:
            instruction_words += len(re.findall(pattern, content, re.IGNORECASE))

        total_words = len(content.split())
        if total_words == 0:
            return 0.0

        return instruction_words / total_words

    def _has_hidden_content(self, content: str) -> bool:
        """Check for hidden content patterns."""
        patterns = [
            r"<!--.*?-->",  # HTML comments
            r"/\*.*?\*/",  # C-style comments
            r"\x00",  # Null bytes
            r"[\u200b-\u200d\ufeff]",  # Zero-width characters
            r"color:\s*(?:white|transparent)",  # CSS hiding
            r"font-size:\s*0",  # CSS hiding
            r"display:\s*none",  # CSS hiding
        ]
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return True
        return False

    def _has_encoding_attempt(self, content: str) -> bool:
        """Check for encoding/obfuscation attempts."""
        patterns = [
            r"base64[:\s]",
            r"\\x[0-9a-fA-F]{2}",  # Hex escapes
            r"\\u[0-9a-fA-F]{4}",  # Unicode escapes
            r"&#\d+;",  # HTML entities (numeric)
            r"&[a-z]+;",  # HTML entities (named)
            r"(?:eval|exec)\s*\(",  # Code execution
            r"fromCharCode",  # JS string building
        ]
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def get_pattern_summary(self, analysis: ThreatAnalysis) -> str:
        """Get a human-readable summary of detected patterns."""
        if not analysis.pattern_matches:
            return "No injection patterns detected."

        categories: dict[str, list[str]] = {}
        for match in analysis.pattern_matches:
            if match.category not in categories:
                categories[match.category] = []
            # Truncate long matches
            text = match.matched_text[:50] + "..." if len(match.matched_text) > 50 else match.matched_text
            categories[match.category].append(text)

        lines = [f"Detected {len(analysis.pattern_matches)} injection pattern(s):"]
        for category, matches in categories.items():
            lines.append(f"  [{category}]: {len(matches)} match(es)")
            for m in matches[:3]:  # Show up to 3 examples
                lines.append(f"    - \"{m}\"")
            if len(matches) > 3:
                lines.append(f"    ... and {len(matches) - 3} more")

        return "\n".join(lines)
