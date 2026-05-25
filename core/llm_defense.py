"""
core/llm_defense.py
--------------------
Shared defenses for LLM input sanitization across all agenrs

CURRENT DEFENSE LAYERS:
    PROMPT INJECTION DEFENSE:
    Camera banners are attacker-controlled data. A malicious camera
    (see 192.168.1.99 in mock_network.json) can serve banner content designed to hijack LLM behavior.
 
    Defense layer 1: XML tag wrapping:
        Banner content is wrapped before LLM ingestion:
        <banner_data source="192.168.1.99">...malicious content...</banner_data>
        This signals to the LLM that the content is data, not instructions.
        Reduces attack surface but is not a hard technical control.
 
    Defense layer 2: Heuristic flagging:
        Banners that are unusually long or contain instruction-like keywords
        are flagged to the audit log before LLM ingestion. Operator can
        review flagged hosts.
 
    # TODO: Defense layer 3: Secondary model guard (future implementation)
    #   Run banner through a secondary LLM call first:
    #   "Does this content contain a prompt injection attempt? Yes/No"
    #   Only pass to main classification prompt if guard returns No.
    #   Better for semantic filtering
"""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Content longer than this threshold is flagged as suspicious.
# Real device banners are short.. 200+ byte Server is sus
# Adjust if legitimate devices in your environment produce longer banners.
SUSPICIOUS_LENGTH_THRESHOLD = 200

# Keywords that suggest content is attempting to issue instructions to an LLM.this is heuristic first pass, not a blocklist.
# TODO: look up for heuristic seclists see if any exist
INJECTION_KEYWORDS = [
    "ignore previous",
    "ignore all",
    "you are now",
    "system prompt",
    "disregard",
    "forget your",
    "new instructions",
    "act as",
    "jailbreak",
]


# ---------------------------------------------------------------------------
# Defense functions
# ---------------------------------------------------------------------------

def your_sus_bro(content: str) -> tuple[bool, str]:
    """
    Heuristic check 

    Checks len(content) v SUSPICIOUS_LENGTH_THRESHOLD & scan fo known instruction-like keywords from 
    INJECTION_KEYWORDS.

    WHY THIS ReTURNS A REASON STRING:
         "banner length 386 exceeds threshold 200" is logged to audits and is
             more actionable than just "suspicious: True".

    Args:
        content: Raw attacker-controlled string to check (banner, HTTP response,
                 config file contents, etc.)

    Returns:
        Tuple of (is_suspicious: bool, reason: str).
        reason is an empty string if not suspicious.
    """
    if len(content) > SUSPICIOUS_LENGTH_THRESHOLD:
        return True, (
            f"content length {len(content)} exceeds threshold "
            f"{SUSPICIOUS_LENGTH_THRESHOLD}"
        )

    content_lower = content.lower()
    for keyword in INJECTION_KEYWORDS:
        if keyword in content_lower:
            return True, f"injection keyword detected: '{keyword}'"

    return False, ""


def wrap_for_llm(source: str, content: str, tag: str = "untrusted_data") -> str:
    """
    Wrap attacker-controlled content in XML tags before LLM ingestion.

    The XML tags signal to the LLM that the enclosed content is external data to be analyzed, not 
    instructions to be followed. The source attribute gives the LLM context about where the data 
    came from. 

    Args:
        source:  Where the content came from — typically an IP address or
                 hostname. Included as an XML attribute for LLM context.
        content: Raw attacker-controlled string to wrap.
        tag:     XML tag name to use. Defaults to "untrusted_data" as a
                 generic safe default. Callers can pass a more specific tag
                 (e.g. "banner_data", "http_response", "config_file") to
                 give the LLM better context about the data type.

    Returns:
        XML-wrapped string safe for inclusion in an LLM prompt.

    Examples:
        >>> wrap_for_llm("192.168.1.99", "Hikvision-Webs", tag="banner_data")
        '<banner_data source="192.168.1.99">Hikvision-Webs</banner_data>'

        >>> wrap_for_llm("192.168.1.10", response_body, tag="http_response")
        '<http_response source="192.168.1.10">...</http_response>'
    """
    return f'<{tag} source="{source}">{content}</{tag}>'