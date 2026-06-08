"""Risk scoring logic. Deterministic 0-100 composite score."""
from aegis.models import Finding


SEVERITY_MULTIPLIER = {
    "info": 0.1,
    "low": 0.3,
    "medium": 0.6,
    "high": 0.85,
    "critical": 1.0,
}

RISK_LEVELS = [
    (0, 20, "Minimal"),
    (20, 40, "Low"),
    (40, 60, "Moderate"),
    (60, 80, "High"),
    (80, 101, "Critical"),
]


def score(findings: list[Finding]) -> tuple[float, str]:
    """Compute composite score (0-100) and risk level from findings list."""
    if not findings:
        return 0.0, "Minimal"

    raw = sum(f.weight * SEVERITY_MULTIPLIER[f.severity] for f in findings)
    norm = min(100.0, raw * 10)

    for lo, hi, name in RISK_LEVELS:
        if lo <= norm < hi:
            return norm, name
    return norm, "Critical"


def detect_lethal_trifecta(tools: list) -> dict:
    """
    Detects Simon Willison's "lethal trifecta":
    private data access + untrusted content + external communication.
    """
    has_private_data = False
    has_untrusted_content = False
    has_external_comms = False

    private_indicators = ["database", "secret", "credential", "user_data", "pii",
                          "lookup", "query", "fetch_user", "get_account"]
    untrusted_indicators = ["web_fetch", "url_fetch", "html", "pdf", "document_loader",
                            "rag", "crawl", "scrape", "fetch_url", "load_url"]
    external_indicators = ["send_email", "post_webhook", "publish", "http_post",
                           "send_message", "notify", "tweet", "slack"]

    for tool in tools:
        name = tool.name.lower()
        desc = (tool.description or "").lower()
        combined = name + " " + desc

        if any(ind in combined for ind in private_indicators):
            has_private_data = True
        if any(ind in combined for ind in untrusted_indicators):
            has_untrusted_content = True
        if any(ind in combined for ind in external_indicators):
            has_external_comms = True

    return {
        "private_data_access": has_private_data,
        "untrusted_content_ingestion": has_untrusted_content,
        "external_communication": has_external_comms,
        "trifecta_present": has_private_data and has_untrusted_content and has_external_comms,
    }
