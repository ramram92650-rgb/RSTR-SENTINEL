import re


TRUSTED_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "linkedin.com",
    "github.com",
}


def extract_domain(sender: str) -> str:
    match = re.search(r"@([a-zA-Z0-9.-]+)", sender)

    if match:
        return match.group(1).lower()

    return ""


def analyze_domain(sender: str) -> dict:

    domain = extract_domain(sender)

    if not domain:
        return {
            "domain": "",
            "domain_status": "INVALID",
            "domain_risk": 30,
            "reason": "Unable to extract sender domain"
        }

    if domain in TRUSTED_DOMAINS:
        return {
            "domain": domain,
            "domain_status": "TRUSTED",
            "domain_risk": 0,
            "reason": "Sender domain belongs to a trusted domain"
        }

    suspicious_patterns = [
        "0",
        "1",
        "-",
        "secure",
        "support",
        "verify",
        "login",
        "account",
        "alert"
    ]

    detected_patterns = [
        pattern
        for pattern in suspicious_patterns
        if pattern in domain
    ]

    if detected_patterns:

        risk = min(
            20 + len(detected_patterns) * 10,
            60
        )

        return {
            "domain": domain,
            "domain_status": "SUSPICIOUS",
            "domain_risk": risk,
            "reason": "Suspicious domain pattern detected",
            "detected_patterns": detected_patterns
        }

    return {
        "domain": domain,
        "domain_status": "UNKNOWN",
        "domain_risk": 10,
        "reason": "Domain is not in the trusted domain list"
    }