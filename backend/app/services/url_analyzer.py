import re
from urllib.parse import urlparse


def extract_urls(text: str) -> list[str]:
    """
    Extract HTTP/HTTPS URLs from email text.
    """
    url_pattern = r"https?://[^\s<>\"]+"
    return re.findall(url_pattern, text)


def is_ip_address(domain: str) -> bool:
    """
    Check whether the domain is an IPv4 address.
    """
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(ip_pattern, domain))


def analyze_url(url: str) -> dict:
    """
    Analyze a single URL for common phishing indicators.
    """

    parsed = urlparse(url)

    if not parsed.netloc:
        return {
            "url": url,
            "status": "INVALID",
            "risk": 30,
            "indicators": ["Invalid URL"]
        }

    domain = parsed.netloc.lower()
    indicators = []
    risk = 0

    # 1. IP address instead of domain
    if is_ip_address(domain):
        indicators.append(
            "IP address used instead of domain"
        )
        risk += 30

    # 2. Suspicious keywords
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

    # 3. @ symbol
    if "@" in url:
        indicators.append(
            "URL contains @ symbol"
        )
        risk += 25

    # 4. Excessive subdomains
    if not is_ip_address(domain):
        domain_parts = domain.split(".")

        if len(domain_parts) >= 4:
            indicators.append(
                "Excessive subdomains"
            )
            risk += 15

    # 5. Very long URL
    if len(url) > 100:
        indicators.append(
            "Unusually long URL"
        )
        risk += 10

    risk = min(risk, 100)

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


def analyze_urls(text: str) -> dict:
    """
    Extract and analyze all URLs from an email.
    """

    urls = extract_urls(text)

    results = [
        analyze_url(url)
        for url in urls
    ]

    if not results:
        return {
            "url_count": 0,
            "overall_risk": 0,
            "urls": [],
            "message": "No URLs detected"
        }

    overall_risk = max(
        result["risk"]
        for result in results
    )

    return {
        "url_count": len(urls),
        "overall_risk": overall_risk,
        "urls": results
    }