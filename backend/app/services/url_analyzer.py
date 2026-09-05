import re
from urllib.parse import urlparse


# --------------------------------
# URL Extraction
# --------------------------------

def extract_urls(text: str) -> list[str]:
    """
    Extract HTTP/HTTPS URLs from email text.
    """

    if not text:
        return []

    url_pattern = r"https?://[^\s<>\"]+"

    return re.findall(
        url_pattern,
        text,
        re.IGNORECASE
    )


# --------------------------------
# IP Address Detection
# --------------------------------

def is_ip_address(domain: str) -> bool:
    """
    Detect whether a domain is an IPv4 address.
    """

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    return bool(
        re.match(
            ip_pattern,
            domain
        )
    )


# --------------------------------
# Single URL Analysis
# --------------------------------

def analyze_url(url: str) -> dict:
    """
    RSTR SENTINEL URL Intelligence Engine.

    Detects suspicious URL characteristics:
    - IP-based URLs
    - Suspicious keywords
    - @ symbol
    - Excessive subdomains
    - Unusually long URLs
    """

    parsed = urlparse(url)

    if not parsed.netloc:

        return {
            "url": url,
            "status": "INVALID",
            "risk": 30,
            "indicators": [
                "Invalid URL"
            ]
        }

    # Remove username/password information if present
    domain = parsed.hostname or ""

    domain = domain.lower()

    indicators = []

    risk = 0

    # --------------------------------
    # 1. IP Address Detection
    # --------------------------------

    if is_ip_address(domain):

        indicators.append(
            "IP address used instead of domain"
        )

        risk += 30

    # --------------------------------
    # 2. Suspicious Keyword Detection
    # --------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "account",
        "secure",
        "update",
        "password",
        "credential",
        "confirm"
    ]

    for keyword in suspicious_keywords:

        if keyword in url.lower():

            indicators.append(
                f"Suspicious keyword: {keyword}"
            )

            risk += 10

    # --------------------------------
    # 3. @ Symbol Detection
    # --------------------------------

    if "@" in url:

        indicators.append(
            "URL contains @ symbol"
        )

        risk += 25

    # --------------------------------
    # 4. Excessive Subdomain Detection
    # --------------------------------

    if not is_ip_address(domain):

        domain_parts = domain.split(".")

        if len(domain_parts) >= 4:

            indicators.append(
                "Excessive subdomains"
            )

            risk += 15

    # --------------------------------
    # 5. Long URL Detection
    # --------------------------------

    if len(url) > 100:

        indicators.append(
            "Unusually long URL"
        )

        risk += 10

    # --------------------------------
    # 6. Final URL Risk
    # --------------------------------

    risk = min(
        risk,
        100
    )

    if risk >= 70:

        status = "HIGH"

    elif risk >= 40:

        status = "MEDIUM"

    else:

        status = "LOW"

    return {
        "url": url,
        "domain": domain,
        "status": status,
        "risk": risk,
        "indicators": indicators
    }


# --------------------------------
# Multiple URL Analysis
# --------------------------------

def analyze_urls(text: str) -> dict:
    """
    Analyze all URLs found inside the email.
    """

    urls = extract_urls(text)

    results = [
        analyze_url(url)
        for url in urls
    ]

    # --------------------------------
    # No URLs
    # --------------------------------

    if not results:

        return {
            "url_count": 0,
            "overall_risk": 0,
            "urls": [],
            "message": "No URLs detected"
        }

    # --------------------------------
    # Overall Risk
    # --------------------------------

    overall_risk = max(
        result["risk"]
        for result in results
    )

    return {
        "url_count": len(urls),
        "overall_risk": overall_risk,
        "urls": results
    }