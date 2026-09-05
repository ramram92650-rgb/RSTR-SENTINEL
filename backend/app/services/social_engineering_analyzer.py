import re


def analyze_social_engineering(
    subject: str,
    body: str
) -> dict:
    """
    RSTR SENTINEL - Social Engineering Detection

    Hackathon MVP:
    Detects common psychological manipulation techniques
    used in phishing and social engineering attacks.

    This is a local, explainable rule-based NLP engine.
    Email content is not sent to external services.
    """

    text = f"{subject} {body}".lower()

    indicators = []
    evidence = []
    score = 0

    # --------------------------------
    # 1. Urgency / Pressure
    # --------------------------------

    urgency_patterns = [
        "urgent",
        "immediately",
        "act now",
        "right away",
        "as soon as possible",
        "within 24 hours",
        "within 1 hour",
        "final warning",
        "last warning",
        "deadline",
        "time sensitive"
    ]

    detected = detect_patterns(text, urgency_patterns)

    if detected:
        indicators.append("Urgency / pressure")
        evidence.extend(detected)
        score += min(len(detected) * 8, 20)

    # --------------------------------
    # 2. Authority / Impersonation
    # --------------------------------

    authority_patterns = [
        "ceo",
        "chief executive",
        "manager",
        "director",
        "administrator",
        "security team",
        "it department",
        "hr department",
        "bank manager",
        "government official",
        "official notice",
        "authorized personnel"
    ]

    detected = detect_patterns(text, authority_patterns)

    if detected:
        indicators.append("Authority impersonation")
        evidence.extend(detected)
        score += min(len(detected) * 8, 20)

    # --------------------------------
    # 3. Fear / Threat
    # --------------------------------

    fear_patterns = [
        "account will be suspended",
        "account suspended",
        "account will be blocked",
        "account blocked",
        "lose access",
        "legal action",
        "penalty",
        "fine",
        "arrest",
        "security breach",
        "unauthorized access",
        "your account is at risk"
    ]

    detected = detect_patterns(text, fear_patterns)

    if detected:
        indicators.append("Fear / threat manipulation")
        evidence.extend(detected)
        score += min(len(detected) * 10, 20)

    # --------------------------------
    # 4. Reward / Bait
    # --------------------------------

    reward_patterns = [
        "you have won",
        "you are selected",
        "congratulations",
        "free gift",
        "free reward",
        "cash prize",
        "claim your reward",
        "exclusive offer",
        "bonus",
        "refund available",
        "you are eligible"
    ]

    detected = detect_patterns(text, reward_patterns)

    if detected:
        indicators.append("Reward / bait")
        evidence.extend(detected)
        score += min(len(detected) * 8, 15)

    # --------------------------------
    # 5. Financial Manipulation
    # --------------------------------

    financial_patterns = [
        "wire transfer",
        "bank transfer",
        "transfer money",
        "send money",
        "payment required",
        "make a payment",
        "invoice",
        "bank details",
        "credit card",
        "debit card",
        "gift card",
        "payment immediately"
    ]

    detected = detect_patterns(text, financial_patterns)

    if detected:
        indicators.append("Financial manipulation")
        evidence.extend(detected)
        score += min(len(detected) * 10, 20)

    # --------------------------------
    # 6. Trust / Familiarity Exploitation
    # --------------------------------

    trust_patterns = [
        "as discussed",
        "as requested",
        "please keep this confidential",
        "do not tell anyone",
        "keep this private",
        "confidential",
        "between you and me",
        "trusted employee",
        "you can trust me",
        "important internal request"
    ]

    detected = detect_patterns(text, trust_patterns)

    if detected:
        indicators.append("Trust exploitation")
        evidence.extend(detected)
        score += min(len(detected) * 8, 15)

    # --------------------------------
    # 7. Secrecy / Isolation
    # --------------------------------

    secrecy_patterns = [
        "do not share",
        "do not forward",
        "keep this secret",
        "do not contact support",
        "do not contact anyone",
        "do not tell your manager",
        "do not discuss this"
    ]

    detected = detect_patterns(text, secrecy_patterns)

    if detected:
        indicators.append("Secrecy / isolation tactic")
        evidence.extend(detected)
        score += min(len(detected) * 8, 15)

    # --------------------------------
    # Final Score
    # --------------------------------

    score = min(score, 100)

    if score >= 70:
        threat_level = "HIGH"
    elif score >= 40:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    return {
        "social_engineering_detected": score >= 40,
        "social_engineering_score": score,
        "threat_level": threat_level,
        "indicators": list(dict.fromkeys(indicators)),
        "evidence": list(dict.fromkeys(evidence))
    }


def detect_patterns(
    text: str,
    patterns: list[str]
) -> list[str]:
    """
    Detect social-engineering phrases in text.
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