"""Detection patterns for prompt injection attacks."""

# Pattern weights by category
CATEGORY_WEIGHTS: dict[str, int] = {
    "ignore_previous": 25,
    "role_injection": 20,
    "authority_claims": 30,
    "delimiter_attacks": 35,
    "exfiltration": 40,
    "dangerous_commands": 45,
}

# Injection patterns by category
INJECTION_PATTERNS: dict[str, list[str]] = {
    # Instruction override attempts
    "ignore_previous": [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|context|rules?|prompts?)",
        r"disregard\s+(all\s+)?(previous|prior|above)",
        r"forget\s+(all\s+)?(previous|prior|above)",
        r"ignore\s+what\s+(you\s+were|i)\s+(told|said)",
        r"override\s+(previous|prior|above)",
        r"new\s+instructions?:",
        r"updated?\s+instructions?:",
        r"real\s+instructions?:",
        r"actual\s+instructions?:",
        r"start\s+over",
        r"reset\s+(?:your\s+)?(?:instructions?|context|rules?)",
    ],
    # Role injection
    "role_injection": [
        r"you\s+are\s+now\s+(?:a|an|the)",
        r"act\s+as\s+(?:if\s+you\s+are|a|an)",
        r"pretend\s+(?:to\s+be|you\s+are)",
        r"new\s+(?:role|identity|persona)",
        r"assume\s+the\s+(?:role|identity)",
        r"switch\s+to\s+(?:a\s+)?(?:different|new)\s+(?:mode|persona)",
        r"become\s+(?:a|an|the)",
        r"transform\s+into",
        r"roleplay\s+as",
        r"impersonate",
    ],
    # Authority claims
    "authority_claims": [
        r"admin(?:istrator)?\s+(?:mode|override|access|command)",
        r"developer\s+mode",
        r"debug\s+mode",
        r"maintenance\s+mode",
        r"jailbreak",
        r"DAN\s+mode",
        r"god\s+mode",
        r"root\s+access",
        r"sudo\s+mode",
        r"override\s+(?:safety|security|restrictions?)",
        r"bypass\s+(?:safety|security|restrictions?|filters?)",
        r"disable\s+(?:safety|security|restrictions?|filters?)",
        r"unlock\s+(?:hidden|secret|full)\s+(?:features?|capabilities?|mode)",
        r"emergency\s+(?:override|access|mode)",
        r"special\s+(?:access|permissions?|privileges?)",
    ],
    # Delimiter attacks
    "delimiter_attacks": [
        r"</?(system|user|assistant|human|ai|bot)>",
        r"```\s*(?:system|prompt|instruction|config)",
        r"\[INST\]|\[/INST\]",
        r"<\|im_start\|>|<\|im_end\|>",
        r"<\|system\|>|<\|user\|>|<\|assistant\|>",
        r"<<SYS>>|<</SYS>>",
        r"\[system\]|\[/system\]",
        r"###\s*(?:System|User|Assistant|Instruction)",
        r"Human:|Assistant:|System:",
        r"<\|endoftext\|>",
        r"<\|pad\|>",
        r"<s>|</s>",
    ],
    # Exfiltration attempts
    "exfiltration": [
        r"send\s+(?:to|all|this|the|my)\s+.{0,30}@",
        r"forward\s+(?:to|all|this|the)",
        r"email\s+.{0,30}\s+to\s+.{0,20}@",
        r"post\s+(?:to|on)\s+(?:pastebin|gist|hastebin|ghostbin)",
        r"upload\s+(?:to|on)\s+(?:pastebin|gist|hastebin|dropbox|drive)",
        r"share\s+(?:with|to)\s+.{0,20}@",
        r"copy\s+(?:to|into)\s+.{0,30}(?:clipboard|external|remote)",
        r"webhook\s*[:=]",
        r"curl\s+.{0,50}(?:-d|--data)",
        r"fetch\s*\(.{0,50}(?:method|body)",
        r"exfiltrate",
        r"leak\s+(?:the|this|all)",
        r"extract\s+(?:and\s+)?(?:send|upload|post)",
    ],
    # Dangerous commands
    "dangerous_commands": [
        r"(?:rm|del|delete)\s+(?:-rf?\s+)?[/~]",
        r"curl\s+.{0,50}\s*\|\s*(?:ba)?sh",
        r"wget\s+.{0,50}\s*(?:&&|\|)",
        r"eval\s*\(",
        r"exec\s*\(",
        r"(?:python|node|ruby|perl)\s+-c",
        r"base64\s+(?:-d|--decode)",
        r"chmod\s+(?:\+x|777|755)",
        r"chown\s+",
        r"mkfs",
        r"dd\s+if=",
        r">\s*/dev/sd[a-z]",
        r"format\s+[a-z]:",
        r"reg\s+(?:add|delete)",
        r"powershell\s+(?:-enc|-e\s)",
        r"certutil\s+(?:-decode|-urlcache)",
        r"bitsadmin",
        r"nc\s+(?:-e|-c)",
        r"reverse\s*shell",
        r"bind\s*shell",
        r"meterpreter",
        r"mimikatz",
        r"(?:~|\.)/\.ssh",
        r"(?:cat|type)\s+.{0,30}(?:password|secret|key|token|credential)",
        r"(?:env|printenv|set)\s*\|",
    ],
}

# Tool classifications by risk tier
TOOL_TIERS: dict[str, list[str]] = {
    "tier_1_safe": [
        "get_weather",
        "get_time",
        "get_date",
        "read_calendar",
        "search_web",
        "read_file",
        "list_directory",
        "get_clipboard",
        "calculator",
        "unit_convert",
        "translate",
        "define_word",
        "get_stock_price",
    ],
    "tier_2_moderate": [
        "send_email",
        "send_message",
        "post_to_slack",
        "post_to_discord",
        "create_calendar_event",
        "write_file",
        "create_file",
        "append_file",
        "update_document",
        "create_reminder",
        "send_notification",
        "post_tweet",
        "create_issue",
        "comment_on_issue",
    ],
    "tier_3_sensitive": [
        "execute_shell",
        "execute_command",
        "run_script",
        "run_python",
        "run_code",
        "bash",
        "shell",
        "terminal",
        "delete_file",
        "move_file",
        "rename_file",
        "access_keychain",
        "read_credentials",
        "browser_navigate",
        "browser_click",
        "browser_type",
        "http_request",
        "api_call",
        "database_query",
        "sql_execute",
        "install_package",
        "pip_install",
        "npm_install",
    ],
    "tier_4_critical": [
        "sudo_execute",
        "admin_command",
        "bulk_delete",
        "format_disk",
        "transfer_funds",
        "send_crypto",
        "send_payment",
        "modify_system_config",
        "change_password",
        "create_user",
        "delete_user",
        "grant_permissions",
        "revoke_permissions",
        "ssh_connect",
        "remote_execute",
        "deploy_application",
        "modify_firewall",
        "update_dns",
    ],
}


def get_tier_for_tool(tool_name: str, overrides: dict[str, int] | None = None) -> int:
    """Get the risk tier for a tool.

    Args:
        tool_name: The name of the tool
        overrides: Optional dict of tool name -> tier overrides

    Returns:
        Risk tier (1-4), defaults to 3 for unknown tools
    """
    # Check overrides first
    if overrides and tool_name in overrides:
        return overrides[tool_name]

    # Normalize tool name for matching
    normalized = tool_name.lower().replace("-", "_").replace(" ", "_")

    # Check each tier
    for tier_name, tools in TOOL_TIERS.items():
        tier_num = int(tier_name.split("_")[1])
        for tool in tools:
            if normalized == tool or normalized.endswith(f"_{tool}") or tool in normalized:
                return tier_num

    # Default to tier 3 (sensitive) for unknown tools
    return 3
