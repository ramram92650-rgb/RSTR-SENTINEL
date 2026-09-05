def calculate_risk(
    keyword_risk: int,
    domain_risk: int,
    sender_risk: int,
    url_risk: int
) -> dict:
    """
    RSTR SENTINEL Explainable Risk Engine

    Combines risk signals from:
    - Keyword analysis
    - Domain analysis
    - Sender / Reply-To analysis
    - URL analysis
    """

    raw_score = (
        keyword_risk
        + domain_risk
        + sender_risk
        + url_risk
    )

    final_score = min(raw_score, 100)

    if final_score >= 70:
        threat_level = "HIGH"
    elif final_score >= 40:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    return {
        "keyword_risk": keyword_risk,
        "domain_risk": domain_risk,
        "sender_risk": sender_risk,
        "url_risk": url_risk,
        "raw_score": raw_score,
        "final_score": final_score,
        "threat_level": threat_level
    }