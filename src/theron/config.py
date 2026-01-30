"""Configuration management for Theron."""

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

# Hardcoded allowed API endpoints - SECURITY: prevents SSRF
ALLOWED_ENDPOINTS = frozenset({
    "https://api.anthropic.com",
    "https://api.openai.com",
})


class ProxyConfig(BaseModel):
    """Proxy server configuration."""

    listen_port: int = 8081
    # SECURITY: Endpoints are hardcoded and cannot be overridden via config
    timeout: int = 120
    passthrough_auth: bool = True

    @property
    def endpoints(self) -> dict[str, str]:
        """Return hardcoded endpoints - not configurable for security."""
        return {
            "anthropic": "https://api.anthropic.com",
            "openai": "https://api.openai.com",
        }


class DetectionConfig(BaseModel):
    """Detection engine configuration."""

    sensitivity: int = Field(default=5, ge=1, le=10)
    injection_threshold: int = Field(default=70, ge=0, le=100)
    categories: dict[str, bool] = Field(
        default_factory=lambda: {
            "ignore_previous": True,
            "role_injection": True,
            "authority_claims": True,
            "delimiter_attacks": True,
            "exfiltration": True,
            "dangerous_commands": True,
        }
    )
    custom_patterns: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("custom_patterns")
    @classmethod
    def validate_patterns(cls, patterns: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate custom patterns for security (ReDoS prevention)."""
        validated = []
        for p in patterns:
            pattern = p.get("pattern", "")
            if not pattern or len(pattern) > 500:  # Limit pattern length
                continue
            # Check for dangerous ReDoS patterns
            if cls._is_redos_vulnerable(pattern):
                continue  # Skip dangerous patterns silently
            try:
                re.compile(pattern)
                validated.append(p)
            except re.error:
                continue  # Skip invalid patterns
        return validated

    @staticmethod
    def _is_redos_vulnerable(pattern: str) -> bool:
        """Check if pattern is potentially vulnerable to ReDoS."""
        # Patterns with nested quantifiers are dangerous
        dangerous_patterns = [
            r'\(\[?[^)]*[+*]\)?[+*]',  # (a+)+ or [a+]+ patterns
            r'\([^)]+\|[^)]+\)[+*]',   # (a|b)+ alternation with quantifier
            r'\.+\*',                   # .+* or .*+
            r'\*\+',                    # *+
            r'\+\+',                    # ++
        ]
        for dp in dangerous_patterns:
            if re.search(dp, pattern):
                return True
        return False


class ClassificationConfig(BaseModel):
    """Action classification configuration."""

    unknown_tool_tier: int = Field(default=3, ge=1, le=4)
    tool_overrides: dict[str, int] = Field(default_factory=dict)


class GatingConfig(BaseModel):
    """Gating policy configuration."""

    whitelist: list[str] = Field(default_factory=list)
    blacklist: list[str] = Field(default_factory=list)
    overrides: dict[str, str] = Field(default_factory=dict)


class DashboardConfig(BaseModel):
    """Dashboard configuration."""

    enabled: bool = True
    port: int = 8080


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    retention_days: int = 30
    log_bodies: bool = False


class LearningConfig(BaseModel):
    """Learning configuration (v2)."""

    enabled: bool = False
    baseline_days: int = 7
    anomaly_sensitivity: int = 5


class TheronConfig(BaseModel):
    """Main Theron configuration."""

    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    classification: ClassificationConfig = Field(default_factory=ClassificationConfig)
    gating: GatingConfig = Field(default_factory=GatingConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    learning: LearningConfig = Field(default_factory=LearningConfig)


def get_config_dir() -> Path:
    """Get the Theron configuration directory."""
    config_dir = Path(os.environ.get("THERON_CONFIG_DIR", Path.home() / ".theron"))
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_config_path() -> Path:
    """Get the path to the configuration file."""
    return get_config_dir() / "config.yaml"


def get_default_config() -> str:
    """Get the default configuration as YAML string."""
    return """# Theron Configuration
# Security layer for agentic AI systems

#----------------------------------------------------------------------
# PROXY SETTINGS
#----------------------------------------------------------------------
proxy:
  listen_port: 8081
  timeout: 120
  passthrough_auth: true
  # NOTE: API endpoints are hardcoded for security and cannot be changed

#----------------------------------------------------------------------
# DETECTION SETTINGS
#----------------------------------------------------------------------
detection:
  # Sensitivity: 1 (permissive) to 10 (strict)
  sensitivity: 5

  # Threat score threshold (0-100)
  injection_threshold: 70

  # Enable/disable detection categories
  categories:
    ignore_previous: true
    role_injection: true
    authority_claims: true
    delimiter_attacks: true
    exfiltration: true
    dangerous_commands: true

  # Custom patterns (regex)
  custom_patterns: []
    # - pattern: "send.*to.*@protonmail"
    #   weight: 30
    #   description: "Suspicious email exfiltration"

#----------------------------------------------------------------------
# ACTION CLASSIFICATION
#----------------------------------------------------------------------
classification:
  unknown_tool_tier: 3

  tool_overrides: {}
    # my_safe_tool: 1
    # my_dangerous_tool: 4

#----------------------------------------------------------------------
# GATING POLICY
#----------------------------------------------------------------------
gating:
  whitelist: []
    # - get_weather
    # - get_time

  blacklist: []
    # - format_disk

  # Override specific combinations: "SOURCE:TOOL" -> "allow|log|block"
  overrides: {}
    # "CONTENT_READ:send_email": "block"

#----------------------------------------------------------------------
# DASHBOARD
#----------------------------------------------------------------------
dashboard:
  enabled: true
  port: 8080

#----------------------------------------------------------------------
# LOGGING
#----------------------------------------------------------------------
logging:
  level: INFO
  retention_days: 30
  log_bodies: false

#----------------------------------------------------------------------
# LEARNING (v2)
#----------------------------------------------------------------------
learning:
  enabled: false
  baseline_days: 7
  anomaly_sensitivity: 5
"""


def create_default_config() -> Path:
    """Create the default configuration file."""
    config_path = get_config_path()
    if not config_path.exists():
        config_path.write_text(get_default_config())
    return config_path


def load_config() -> TheronConfig:
    """Load configuration from file or create default."""
    config_path = get_config_path()

    if not config_path.exists():
        create_default_config()

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        return TheronConfig(**data)
    except Exception as e:
        raise ValueError(f"Invalid configuration file: {e}") from e


def save_config(config: TheronConfig) -> None:
    """Save configuration to file."""
    config_path = get_config_path()
    data = config.model_dump()

    with open(config_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# Global config instance
_config: TheronConfig | None = None


def get_config() -> TheronConfig:
    """Get the current configuration (loads if not already loaded)."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config() -> TheronConfig:
    """Reload configuration from file."""
    global _config
    _config = load_config()
    return _config
