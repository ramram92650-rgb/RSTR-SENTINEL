import re


def analyze_phishing_intent(
    subject: str,
    body: str
) -> dict:
    """
    RSTR SENTINEL - AI Phishing Analysis

    Hackathon MVP:
    Performs explainable language and intent analysis
    to identify common phishing characteristics.

    This is a local rule-based NLP-style engine.
    It does not send email content to external services.
    """

    text = f"{subject} {body}".lower()

    indicators = []
    evidence = []
    score = 0

    # --------------------------------
    # 1. Urgency Detection
    # --------------------------------

    urgency_patterns = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "final warning",
        "last warning",
        "account will be suspended",
        "account suspended",
        "action required"
    ]

    detected_urgency = detect_patterns(
        text,
        urgency_patterns
    )

    if detected_urgency:
        indicators.append("Urgency / pressure")
        evidence.extend(detected_urgency)
        score += min(
            len(detected_urgency) * 10,
            20
        )

    # --------------------------------
    # 2. Credential Harvesting
    # --------------------------------

    credential_patterns = [
        "password",
        "username",
        "login",
        "credentials",
        "verify your account",
        "confirm your account",
        "sign in",
        "reset your password",
        "authentication"
    ]

    detected_credentials = detect_patterns(
        text,
        credential_patterns
    )

    if detected_credentials:
        indicators.append("Credential harvesting")
        evidence.extend(detected_credentials)
        score += min(
            len(detected_credentials) * 10,
            25
        )

    # --------------------------------
    # 3. Financial Fraud
    # --------------------------------

    financial_patterns = [
        "payment",
        "invoice",
        "bank account",
        "bank details",
        "credit card",
        "debit card",
        "transaction",
        "refund",
        "wire transfer",
        "money transfer"
    ]

    detected_financial = detect_patterns(
        text,
        financial_patterns
    )

    if detected_financial:
        indicators.append("Financial request")
        evidence.extend(detected_financial)
        score += min(
            len(detected_financial) * 10,
            20
        )

    # --------------------------------
    # 4. Suspicious Call To Action
    # --------------------------------

    action_patterns = [
        "click here",
        "click the link",
        "click below",
        "verify now",
        "login now",
        "update now",
        "confirm now",
        "download",
        "open the link"
    ]

    detected_actions = detect_patterns(
        text,
        action_patterns
    )

    if detected_actions:
        indicators.append("Suspicious call-to-action")
        evidence.extend(detected_actions)
        score += min(
            len(detected_actions) * 10,
            20
        )

    # --------------------------------
    # 5. Impersonation Language
    # --------------------------------

    impersonation_patterns = [
        "security team",
        "support team",
        "administrator",
        "it department",
        "customer support",
        "account team",
        "official notice",
        "security alert"
    ]

    detected_impersonation = detect_patterns(
        text,
        impersonation_patterns
    )

    if detected_impersonation:
        indicators.append("Possible impersonation")
        evidence.extend(detected_impersonation)
        score += min(
            len(detected_impersonation) * 10,
            15
        )

    # --------------------------------
    # 6. Threat / Consequence Language
    # --------------------------------

    threat_patterns = [
        "suspended",
        "blocked",
        "terminated",
        "locked",
        "disabled",
        "legal action",
        "penalty",
        "lose access"
    ]

    detected_threats = detect_patterns(
        text,
        threat_patterns
    )

    if detected_threats:
        indicators.append("Threat / consequence pressure")
        evidence.extend(detected_threats)
        score += min(
            len(detected_threats) * 10,
            15
        )

    # --------------------------------
    # 7. Final Score
    # --------------------------------

    score = min(score, 100)

    if score >= 70:
        threat_level = "HIGH"
    elif score >= 40:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    # --------------------------------
    # 8. Phishing Probability
    # --------------------------------

    phishing_probability = score

    return {
        "phishing_detected": score >= 40,
        "phishing_probability": phishing_probability,
        "threat_level": threat_level,
        "risk_score": score,
        "indicators": list(dict.fromkeys(indicators)),
        "evidence": list(dict.fromkeys(evidence))
    }


def detect_patterns(
    text: str,
    patterns: list[str]
) -> list[str]:
    """
    Detect matching phishing-related phrases.
    """

    detected = []

    for pattern in patterns:

        if re.search(
            rf"\b{re.escape(pattern)}\b",
            text,
            re.IGNORECASE
        ):
            detected.append(pattern)

    return detected