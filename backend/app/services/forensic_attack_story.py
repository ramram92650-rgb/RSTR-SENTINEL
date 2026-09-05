def generate_attack_story(
    domain_result: dict,
    sender_result: dict,
    url_result: dict,
    header_result: dict,
    authentication_result: dict,
    phishing_result: dict,
    social_engineering_result: dict,
    correlation_result: dict
) -> dict:
    """
    RSTR SENTINEL - Forensic Attack Story / Reconstruction

    Hackathon MVP:
    Converts independent security signals into a
    human-readable attack narrative.

    Local and explainable.
    No external threat intelligence services required.
    """

    stages = []
    evidence = []

    # --------------------------------
    # Stage 1 - Sender / Infrastructure
    # --------------------------------
    if domain_result.get("domain_status") == "SUSPICIOUS":
        stages.append({
            "stage": 1,
            "name": "Suspicious Sender Infrastructure",
            "description": (
                "The email originated from a domain showing "
                "suspicious characteristics."
            ),
            "evidence": [
                domain_result.get("reason", "Suspicious sender domain")
            ]
        })

        evidence.append("Suspicious sender domain")

    elif domain_result.get("domain_status") == "UNKNOWN":
        stages.append({
            "stage": 1,
            "name": "Unknown Sender Infrastructure",
            "description": (
                "The sender domain is not recognized as a trusted domain."
            ),
            "evidence": [
                domain_result.get("reason", "Unknown sender domain")
            ]
        })

        evidence.append("Unknown sender domain")

    # --------------------------------
    # Stage 2 - Sender Manipulation
    # --------------------------------
    if sender_result.get("mismatch") is True:
        stages.append({
            "stage": 2,
            "name": "Sender Identity Manipulation",
            "description": (
                "The visible sender and Reply-To addresses use "
                "different domains, which may redirect the victim's response."
            ),
            "evidence": [
                "Sender domain: "
                + sender_result.get("sender_domain", ""),
                "Reply-To domain: "
                + sender_result.get("reply_to_domain", "")
            ]
        })

        evidence.append("Sender and Reply-To domains differ")

    # --------------------------------
    # Stage 3 - URL Delivery
    # --------------------------------
    url_risk = url_result.get("overall_risk", 0)

    if url_risk >= 40:
        stages.append({
            "stage": 3,
            "name": "Malicious Link Delivery",
            "description": (
                "The email contains a high-risk URL that may be "
                "used to redirect the victim to attacker-controlled infrastructure."
            ),
            "evidence": [
                f"URL risk score: {url_risk}"
            ]
        })

        evidence.append("High-risk URL detected")

    elif url_result.get("url_count", 0) > 0:
        stages.append({
            "stage": 3,
            "name": "Link Delivery",
            "description": (
                "The email contains one or more URLs that require "
                "additional security analysis."
            ),
            "evidence": [
                f"{url_result.get('url_count', 0)} URL(s) detected"
            ]
        })

        evidence.append("URL detected")

    # --------------------------------
    # Stage 4 - Authentication
    # --------------------------------
    authentication_risk = authentication_result.get(
        "overall_risk",
        0
    )

    if authentication_risk >= 35:
        stages.append({
            "stage": 4,
            "name": "Email Authentication Anomaly",
            "description": (
                "SPF, DKIM, or DMARC authentication results "
                "indicate a possible authentication failure."
            ),
            "evidence": authentication_result.get(
                "issues",
                []
            )
        })

        evidence.append("Email authentication anomaly")

    # --------------------------------
    # Stage 5 - Social Engineering
    # --------------------------------
    social_score = social_engineering_result.get(
        "social_engineering_score",
        0
    )

    if social_score >= 40:
        stages.append({
            "stage": 5,
            "name": "Social Engineering Manipulation",
            "description": (
                "The message uses psychological manipulation such as "
                "urgency, authority, fear, financial pressure, or secrecy."
            ),
            "evidence": social_engineering_result.get(
                "evidence",
                []
            )
        })

        evidence.append("Social engineering detected")

    # --------------------------------
    # Stage 6 - Phishing Intent
    # --------------------------------
    phishing_score = phishing_result.get(
        "risk_score",
        0
    )

    if phishing_score >= 40:
        stages.append({
            "stage": 6,
            "name": "Phishing Intent",
            "description": (
                "The language of the email indicates an attempt "
                "to manipulate the recipient into performing a risky action."
            ),
            "evidence": phishing_result.get(
                "evidence",
                []
            )
        })

        evidence.append("Phishing intent detected")

    # --------------------------------
    # Stage 7 - Coordinated Attack
    # --------------------------------
    if correlation_result.get("correlation_detected") is True:
        stages.append({
            "stage": 7,
            "name": "Coordinated Attack Pattern",
            "description": (
                "Multiple independent security signals combine "
                "to indicate a coordinated attack pattern."
            ),
            "evidence": correlation_result.get(
                "correlations",
                []
            )
        })

        evidence.append("Coordinated threat pattern detected")

    # --------------------------------
    # Determine Attacker Objective
    # --------------------------------
    social_indicators = social_engineering_result.get(
        "indicators",
        []
    )

    phishing_indicators = phishing_result.get(
        "indicators",
        []
    )

    if (
        "Financial manipulation" in social_indicators
        or "Financial request" in phishing_indicators
    ):
        attacker_objective = "Financial Fraud / Unauthorized Payment"

    elif (
        "Credential harvesting" in phishing_indicators
        or phishing_score >= 40
    ):
        attacker_objective = "Credential Theft"

    elif url_risk >= 40:
        attacker_objective = "Malicious Link Delivery"

    elif sender_result.get("mismatch") is True:
        attacker_objective = "Identity Impersonation"

    else:
        attacker_objective = "User Manipulation"

    # --------------------------------
    # Attack Pattern
    # --------------------------------
    attack_pattern = correlation_result.get(
        "attack_pattern",
        "Suspicious Email Activity"
    )

    # --------------------------------
    # Narrative Generation
    # --------------------------------
    narrative_parts = []

    if domain_result.get("domain_status") == "SUSPICIOUS":
        narrative_parts.append(
            "The attack appears to originate from suspicious "
            "sender infrastructure."
        )

    if sender_result.get("mismatch") is True:
        narrative_parts.append(
            "The attacker appears to manipulate the sender identity "
            "by using a different Reply-To domain."
        )

    if url_risk >= 40:
        narrative_parts.append(
            "The email contains a potentially dangerous link "
            "that may be used to redirect the victim."
        )

    if social_score >= 40:
        narrative_parts.append(
            "The message uses social engineering techniques "
            "to influence the victim's decision."
        )

    if phishing_score >= 40:
        narrative_parts.append(
            "The language also indicates phishing intent."
        )

    if (
        "Financial manipulation" in social_indicators
        or "Financial request" in phishing_indicators
    ):
        narrative_parts.append(
            "The likely objective is to convince the victim "
            "to perform an unauthorized financial action."
        )

    if not narrative_parts:
        narrative_parts.append(
            "The available evidence does not indicate a strong "
            "coordinated attack pattern."
        )

    attack_story = " ".join(narrative_parts)

    # --------------------------------
    # Confidence
    # --------------------------------
    correlation_score = correlation_result.get(
        "correlation_score",
        0
    )

    if correlation_score >= 70:
        confidence = "HIGH"
    elif correlation_score >= 40:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "attack_story": attack_story,
        "attack_pattern": attack_pattern,
        "attacker_objective": attacker_objective,
        "confidence": confidence,
        "stages": stages,
        "evidence": list(dict.fromkeys(evidence)),
        "stage_count": len(stages)
    }