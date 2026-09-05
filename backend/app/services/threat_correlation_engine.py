def correlate_threats(
    domain_result: dict,
    sender_result: dict,
    url_result: dict,
    header_result: dict,
    authentication_result: dict,
    phishing_result: dict,
    social_engineering_result: dict
) -> dict:
    """
    RSTR SENTINEL - Threat Correlation Engine

    Combines independent security signals and identifies
    coordinated attack patterns.

    Hackathon MVP:
    Local, explainable correlation logic.
    """

    correlations = []
    evidence = []
    correlation_score = 0

    # --------------------------------
    # 1. Domain + Sender Correlation
    # --------------------------------

    if (
        domain_result.get("domain_status") == "SUSPICIOUS"
        and sender_result.get("mismatch") is True
    ):
        correlations.append(
            "Suspicious sender infrastructure with Reply-To mismatch"
        )
        evidence.extend([
            "Suspicious sender domain",
            "Sender and Reply-To domains differ"
        ])
        correlation_score += 20

    # --------------------------------
    # 2. Authentication Failure
    # --------------------------------

    authentication_risk = authentication_result.get(
        "overall_risk",
        0
    )

    if authentication_risk >= 35:
        correlations.append(
            "Email authentication anomaly detected"
        )
        evidence.append(
            "SPF/DKIM/DMARC authentication risk"
        )
        correlation_score += 15

    # --------------------------------
    # 3. Suspicious URL + Phishing
    # --------------------------------

    url_risk = url_result.get(
        "overall_risk",
        0
    )

    phishing_risk = phishing_result.get(
        "risk_score",
        0
    )

    if url_risk >= 40 and phishing_risk >= 40:
        correlations.append(
            "Suspicious URL combined with phishing intent"
        )
        evidence.extend([
            "High-risk URL detected",
            "Phishing language detected"
        ])
        correlation_score += 20

    # --------------------------------
    # 4. Social Engineering + Financial Activity
    # --------------------------------

    social_score = social_engineering_result.get(
        "social_engineering_score",
        0
    )

    social_indicators = social_engineering_result.get(
        "indicators",
        []
    )

    if (
        social_score >= 40
        and "Financial manipulation" in social_indicators
    ):
        correlations.append(
            "Social engineering combined with financial manipulation"
        )
        evidence.extend([
            "Social engineering detected",
            "Financial manipulation detected"
        ])
        correlation_score += 20

    # --------------------------------
    # 5. Multi-Signal Attack Pattern
    # --------------------------------

    active_signals = 0

    if domain_result.get("domain_risk", 0) >= 20:
        active_signals += 1

    if sender_result.get("risk", 0) >= 20:
        active_signals += 1

    if url_risk >= 20:
        active_signals += 1

    if header_result.get("risk", 0) >= 20:
        active_signals += 1

    if authentication_risk >= 20:
        active_signals += 1

    if phishing_risk >= 40:
        active_signals += 1

    if social_score >= 40:
        active_signals += 1

    if active_signals >= 4:
        correlations.append(
            "Multiple independent threat signals indicate a coordinated attack"
        )
        evidence.append(
            f"{active_signals} independent security signals detected"
        )
        correlation_score += 25

    # --------------------------------
    # Final Score
    # --------------------------------

    correlation_score = min(
        correlation_score,
        100
    )

    if correlation_score >= 70:
        threat_level = "HIGH"
    elif correlation_score >= 40:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    # --------------------------------
    # Attack Pattern Classification
    # --------------------------------

    if (
        social_score >= 40
        and phishing_risk >= 40
        and (
            sender_result.get("mismatch") is True
            or domain_result.get("domain_status") == "SUSPICIOUS"
        )
    ):
        attack_pattern = "Targeted Social Engineering / Phishing"

    elif (
        url_risk >= 40
        and phishing_risk >= 40
    ):
        attack_pattern = "Credential Phishing"

    elif (
        social_score >= 40
        and "Financial manipulation" in social_indicators
    ):
        attack_pattern = "Financial Social Engineering"

    elif sender_result.get("mismatch") is True:
        attack_pattern = "Sender Impersonation"

    else:
        attack_pattern = "No Strong Coordinated Pattern"

    return {
        "correlation_detected": correlation_score >= 40,
        "correlation_score": correlation_score,
        "threat_level": threat_level,
        "attack_pattern": attack_pattern,
        "correlations": list(dict.fromkeys(correlations)),
        "evidence": list(dict.fromkeys(evidence)),
        "active_signals": active_signals
    }