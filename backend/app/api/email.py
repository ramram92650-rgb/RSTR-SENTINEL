from fastapi import APIRouter
from pydantic import BaseModel

from app.services.domain_analyzer import analyze_domain
from app.services.sender_analyzer import analyze_sender
from app.services.url_analyzer import analyze_urls
from app.services.risk_engine import calculate_risk
from app.services.header_forensics import analyze_email_headers
from app.services.email_authentication import extract_authentication_results


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

    domain_result = analyze_domain(
        email.sender
    )

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
    # 7. Base Risk Engine
    # --------------------------------

    risk_result = calculate_risk(
        keyword_risk=keyword_risk,
        domain_risk=domain_risk,
        sender_risk=sender_risk,
        url_risk=url_risk
    )

    risk_score = risk_result["final_score"]

    # --------------------------------
    # 8. Add Header Forensics Risk
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
    # 9. Add Authentication Risk
    # --------------------------------

    risk_score = min(
        risk_score + authentication_risk,
        100
    )

    # --------------------------------
    # 10. Final Threat Classification
    # --------------------------------

    if risk_score >= 70:
        threat_level = "HIGH"

    elif risk_score >= 40:
        threat_level = "MEDIUM"

    else:
        threat_level = "LOW"

    # --------------------------------
    # 11. Final Response
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

        "risk_analysis": {
            **risk_result,

            "header_risk": header_risk,

            "authentication_risk": authentication_risk,

            "final_score": risk_score,

            "threat_level": threat_level
        }
    }