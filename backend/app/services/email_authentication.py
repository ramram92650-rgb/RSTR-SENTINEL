import re


def extract_authentication_results(raw_email: str) -> dict:
    """
    Extract SPF, DKIM and DMARC authentication results
    from the Authentication-Results header.

    This module performs local header analysis for the
    RSTR SENTINEL internal hackathon MVP.
    """

    if not raw_email:
        return {
            "spf": {
                "status": "NOT_AVAILABLE",
                "risk": 0
            },
            "dkim": {
                "status": "NOT_AVAILABLE",
                "risk": 0
            },
            "dmarc": {
                "status": "NOT_AVAILABLE",
                "risk": 0
            },
            "overall_status": "NOT_AVAILABLE",
            "overall_risk": 0,
            "issues": []
        }

    email_text = raw_email.lower()

    spf_status = extract_auth_result(
        email_text,
        "spf"
    )

    dkim_status = extract_auth_result(
        email_text,
        "dkim"
    )

    dmarc_status = extract_auth_result(
        email_text,
        "dmarc"
    )

    spf_risk = calculate_auth_risk(
        spf_status
    )

    dkim_risk = calculate_auth_risk(
        dkim_status
    )

    dmarc_risk = calculate_auth_risk(
        dmarc_status
    )

    issues = []

    if spf_status == "FAIL":
        issues.append(
            "SPF authentication failed"
        )

    if dkim_status == "FAIL":
        issues.append(
            "DKIM authentication failed"
        )

    if dmarc_status == "FAIL":
        issues.append(
            "DMARC authentication failed"
        )

    if spf_status == "NOT_AVAILABLE":
        issues.append(
            "SPF result not available"
        )

    if dkim_status == "NOT_AVAILABLE":
        issues.append(
            "DKIM result not available"
        )

    if dmarc_status == "NOT_AVAILABLE":
        issues.append(
            "DMARC result not available"
        )

    overall_risk = min(
        spf_risk + dkim_risk + dmarc_risk,
        100
    )

    if overall_risk >= 70:
        overall_status = "HIGH"
    elif overall_risk >= 40:
        overall_status = "MEDIUM"
    elif overall_risk > 0:
        overall_status = "LOW"
    else:
        overall_status = "PASS"

    return {
        "spf": {
            "status": spf_status,
            "risk": spf_risk
        },
        "dkim": {
            "status": dkim_status,
            "risk": dkim_risk
        },
        "dmarc": {
            "status": dmarc_status,
            "risk": dmarc_risk
        },
        "overall_status": overall_status,
        "overall_risk": overall_risk,
        "issues": issues
    }


def extract_auth_result(
    email_text: str,
    authentication_type: str
) -> str:
    """
    Extract PASS / FAIL / NEUTRAL / SOFTFAIL / NONE
    result for SPF, DKIM or DMARC.
    """

    pattern = (
        rf"\b{authentication_type}"
        rf"=(pass|fail|softfail|neutral|none|temperror|permerror)"
    )

    match = re.search(
        pattern,
        email_text
    )

    if not match:
        return "NOT_AVAILABLE"

    result = match.group(1).upper()

    return result


def calculate_auth_risk(status: str) -> int:
    """
    Convert authentication status into a risk score.
    """

    risk_map = {
        "PASS": 0,
        "NONE": 5,
        "NEUTRAL": 10,
        "SOFTFAIL": 20,
        "TEMPERROR": 20,
        "PERMERROR": 25,
        "FAIL": 35,
        "NOT_AVAILABLE": 0
    }

    return risk_map.get(
        status,
        10
    )