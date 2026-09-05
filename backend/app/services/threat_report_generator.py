def generate_threat_report(
    sender: str,
    risk_score: int,
    threat_level: str,
    detected_indicators: list,
    domain_result: dict,
    sender_result: dict,
    url_result: dict,
    header_result: dict,
    authentication_result: dict,
    phishing_result: dict,
    social_engineering_result: dict,
    correlation_result: dict,
    forensic_story_result: dict
) -> dict:
    """
    RSTR SENTINEL - Explainable Threat Report Generator

    Hackathon MVP:
    Converts all security analysis results into a
    structured and human-readable threat report.

    Local and explainable.
    No external services required.
    """

    # --------------------------------
    # Threat Summary
    # --------------------------------
    if threat_level == "HIGH":
        summary = (
            "High-risk malicious email detected. "
            "Multiple security signals indicate a strong "
            "possibility of phishing, impersonation, or fraud."
        )

    elif threat_level == "MEDIUM":
        summary = (
            "Suspicious email detected. "
            "Several security indicators require further investigation."
        )

    else:
        summary = (
            "No strong malicious indicators were detected. "
            "The email currently appears to have relatively low risk."
        )

    # --------------------------------
    # Risk Explanation
    # --------------------------------
    risk_factors = []

    if domain_result.get("domain_risk", 0) > 0:
        risk_factors.append({
            "category": "Sender Domain",
            "risk": domain_result.get("domain_risk", 0),
            "reason": domain_result.get(
                "reason",
                "Sender domain requires investigation"
            )
        })

    if sender_result.get("risk", 0) > 0:
        risk_factors.append({
            "category": "Sender / Reply-To",
            "risk": sender_result.get("risk", 0),
            "reason": sender_result.get(
                "reason",
                "Sender identity inconsistency detected"
            )
        })

    if url_result.get("overall_risk", 0) > 0:
        risk_factors.append({
            "category": "URL Intelligence",
            "risk": url_result.get("overall_risk", 0),
            "reason": "Suspicious URL characteristics detected"
        })

    if header_result.get("risk", 0) > 0:
        risk_factors.append({
            "category": "Header Forensics",
            "risk": header_result.get("risk", 0),
            "reason": "Email header inconsistencies detected"
        })

    if authentication_result.get("overall_risk", 0) > 0:
        risk_factors.append({
            "category": "Email Authentication",
            "risk": authentication_result.get(
                "overall_risk",
                0
            ),
            "reason": "SPF/DKIM/DMARC authentication anomaly detected"
        })

    if phishing_result.get("risk_score", 0) > 0:
        risk_factors.append({
            "category": "Phishing Analysis",
            "risk": phishing_result.get(
                "risk_score",
                0
            ),
            "reason": "Phishing-related language or intent detected"
        })

    if social_engineering_result.get(
        "social_engineering_score",
        0
    ) > 0:
        risk_factors.append({
            "category": "Social Engineering",
            "risk": social_engineering_result.get(
                "social_engineering_score",
                0
            ),
            "reason": "Psychological manipulation techniques detected"
        })

    # --------------------------------
    # Evidence Collection
    # --------------------------------
    evidence = []

    evidence.extend(
        detected_indicators
    )

    evidence.extend(
        domain_result.get(
            "detected_patterns",
            []
        )
    )

    evidence.extend(
        header_result.get(
            "issues",
            []
        )
    )

    evidence.extend(
        authentication_result.get(
            "issues",
            []
        )
    )

    evidence.extend(
        phishing_result.get(
            "evidence",
            []
        )
    )

    evidence.extend(
        social_engineering_result.get(
            "evidence",
            []
        )
    )

    evidence.extend(
        correlation_result.get(
            "evidence",
            []
        )
    )

    evidence.extend(
        forensic_story_result.get(
            "evidence",
            []
        )
    )

    evidence = list(
        dict.fromkeys(
            evidence
        )
    )

    # --------------------------------
    # Attack Information
    # --------------------------------
    attack_pattern = forensic_story_result.get(
        "attack_pattern",
        correlation_result.get(
            "attack_pattern",
            "Unknown"
        )
    )

    attacker_objective = forensic_story_result.get(
        "attacker_objective",
        "Unknown"
    )

    confidence = forensic_story_result.get(
        "confidence",
        "LOW"
    )

    # --------------------------------
    # Recommended Action
    # --------------------------------
    if threat_level == "HIGH":

        recommended_action = [
            "Do not click links or open attachments.",
            "Do not reply to the sender.",
            "Verify the request using an independent trusted channel.",
            "Report the email as suspicious.",
            "Quarantine or remove the email if supported by the mail system."
        ]

    elif threat_level == "MEDIUM":

        recommended_action = [
            "Avoid clicking links or opening attachments.",
            "Verify the sender identity.",
            "Investigate suspicious URLs and headers.",
            "Report the email if additional suspicious evidence is found."
        ]

    else:

        recommended_action = [
            "No immediate action required.",
            "Continue normal email security practices.",
            "Re-analyze the email if additional suspicious activity appears."
        ]

    # --------------------------------
    # Forensic Timeline
    # --------------------------------
    timeline = []

    for stage in forensic_story_result.get(
        "stages",
        []
    ):
        timeline.append({
            "stage": stage.get(
                "stage"
            ),
            "event": stage.get(
                "name"
            ),
            "description": stage.get(
                "description"
            )
        })

    # --------------------------------
    # Security Findings
    # --------------------------------
    findings = {
        "domain_status": domain_result.get(
            "domain_status",
            "UNKNOWN"
        ),
        "sender_reply_to_mismatch": sender_result.get(
            "mismatch",
            False
        ),
        "url_count": url_result.get(
            "url_count",
            0
        ),
        "authentication_status": authentication_result.get(
            "overall_status",
            "NOT_AVAILABLE"
        ),
        "phishing_detected": phishing_result.get(
            "phishing_detected",
            False
        ),
        "social_engineering_detected": social_engineering_result.get(
            "social_engineering_detected",
            False
        ),
        "correlation_detected": correlation_result.get(
            "correlation_detected",
            False
        )
    }

    # --------------------------------
    # Final Report
    # --------------------------------
    return {
        "report_title": "RSTR SENTINEL Threat Intelligence Report",

        "sender": sender,

        "risk_score": risk_score,

        "threat_level": threat_level,

        "summary": summary,

        "attack_pattern": attack_pattern,

        "attacker_objective": attacker_objective,

        "confidence": confidence,

        "risk_factors": risk_factors,

        "security_findings": findings,

        "evidence": evidence,

        "forensic_timeline": timeline,

        "recommended_action": recommended_action,

        "report_status": "GENERATED"
    }