from fastapi import APIRouter
from pydantic import BaseModel

from app.services.domain_analyzer import analyze_domain
from app.services.sender_analyzer import analyze_sender
from app.services.url_analyzer import analyze_urls
from app.services.risk_engine import calculate_risk
from app.services.header_forensics import analyze_email_headers
from app.services.email_authentication import extract_authentication_results
from app.services.ai_phishing_analyzer import analyze_phishing_intent
from app.services.social_engineering_analyzer import analyze_social_engineering
from app.services.threat_correlation_engine import correlate_threats


router = APIRouter(
    prefix="/email",
    tags=["Email Security"]
)


class EmailData(BaseModel):
    sender: str
    reply_to: str | None = None
    subject: str
    body: str
    raw_email: str | None = None


@router.post("/analyze")
def analyze_email(email: EmailData):

    # --------------------------------
    # 1. Keyword Detection
    # --------------------------------

    suspicious_keywords = [
        "urgent",
        "verify",
        "password",
        "suspended",
        "click",
        "immediately"
    ]

    text = f"{email.subject} {email.body}".lower()

    detected_indicators = [
        keyword
        for keyword in suspicious_keywords
        if keyword in text
    ]

    keyword_risk = min(
        len(detected_indicators) * 15,
        100
    )

    # --------------------------------
    # 2. Domain Analysis
    # --------------------------------

    domain_result = analyze_domain(email.sender)
    domain_risk = domain_result["domain_risk"]

    # --------------------------------
    # 3. Sender / Reply-To Analysis
    # --------------------------------

    sender_result = analyze_sender(
        email.sender,
        email.reply_to
    )

    sender_risk = sender_result["risk"]

    # --------------------------------
    # 4. URL Intelligence
    # --------------------------------

    url_result = analyze_urls(text)
    url_risk = url_result["overall_risk"]

    # --------------------------------
    # 5. Header Forensics
    # --------------------------------

    if email.raw_email:
        raw_email_bytes = email.raw_email.encode(
            "utf-8",
            errors="ignore"
        )

        header_result = analyze_email_headers(
            raw_email_bytes
        )

    else:
        header_result = {
            "status": "NOT_AVAILABLE",
            "risk": 0,
            "message": "Raw email headers were not provided"
        }

    # --------------------------------
    # 6. SPF / DKIM / DMARC Analysis
    # --------------------------------

    authentication_result = extract_authentication_results(
        email.raw_email or ""
    )

    authentication_risk = authentication_result[
        "overall_risk"
    ]

    # --------------------------------
    # 7. AI Phishing Analysis
    # --------------------------------

    phishing_result = analyze_phishing_intent(
        subject=email.subject,
        body=email.body
    )

    phishing_risk = phishing_result[
        "risk_score"
    ]

    # --------------------------------
    # 8. Social Engineering Analysis
    # --------------------------------

    social_engineering_result = analyze_social_engineering(
        subject=email.subject,
        body=email.body
    )

    social_engineering_risk = social_engineering_result[
        "social_engineering_score"
    ]

    # --------------------------------
    # 9. Base Risk Engine
    # --------------------------------

    risk_result = calculate_risk(
        keyword_risk=keyword_risk,
        domain_risk=domain_risk,
        sender_risk=sender_risk,
        url_risk=url_risk
    )

    risk_score = risk_result["final_score"]

    # --------------------------------
    # 10. Add Header Forensics Risk
    # --------------------------------

    header_risk = header_result.get(
        "risk",
        0
    )

    risk_score = min(
        risk_score + header_risk,
        100
    )

    # --------------------------------
    # 11. Add Authentication Risk
    # --------------------------------

    risk_score = min(
        risk_score + authentication_risk,
        100
    )

    # --------------------------------
    # 12. Add AI Phishing Risk
    # --------------------------------

    risk_score = min(
        risk_score + phishing_risk,
        100
    )

    # --------------------------------
    # 13. Add Social Engineering Risk
    # --------------------------------

    risk_score = min(
        risk_score + social_engineering_risk,
        100
    )

    # --------------------------------
    # 14. Threat Correlation
    # --------------------------------

    correlation_result = correlate_threats(
        domain_result=domain_result,
        sender_result=sender_result,
        url_result=url_result,
        header_result=header_result,
        authentication_result=authentication_result,
        phishing_result=phishing_result,
        social_engineering_result=social_engineering_result
    )

    # --------------------------------
    # 15. Final Threat Classification
    # --------------------------------

    if risk_score >= 70:
        threat_level = "HIGH"
    elif risk_score >= 40:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    # --------------------------------
    # 16. Final Response
    # --------------------------------

    return {
        "sender": email.sender,

        "risk_score": risk_score,
        "threat_level": threat_level,

        "detected_indicators": detected_indicators,

        "domain_analysis": domain_result,

        "sender_analysis": sender_result,

        "url_analysis": url_result,

        "header_forensics": header_result,

        "email_authentication": authentication_result,

        "ai_phishing_analysis": phishing_result,

        "social_engineering_analysis": social_engineering_result,

        "threat_correlation": correlation_result,

        "risk_analysis": {
            **risk_result,
            "header_risk": header_risk,
            "authentication_risk": authentication_risk,
            "phishing_risk": phishing_risk,
            "social_engineering_risk": social_engineering_risk,
            "correlation_score": correlation_result[
                "correlation_score"
            ],
            "final_score": risk_score,
            "threat_level": threat_level
        }
    }