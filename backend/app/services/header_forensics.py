import re
from email import policy
from email.parser import BytesParser


def extract_header_value(headers, name: str) -> str:
    """
    Safely extract a single email header value.
    """
    value = headers.get(name)

    if value is None:
        return ""

    return str(value).strip()


def extract_received_headers(headers) -> list[str]:
    """
    Extract all Received headers.
    """
    return [
        str(value).strip()
        for value in headers.get_all("Received", [])
    ]


def extract_ip_addresses(text: str) -> list[str]:
    """
    Extract IPv4 addresses from header text.
    """
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    return list(dict.fromkeys(
        re.findall(ip_pattern, text)
    ))


def analyze_header_consistency(headers) -> dict:
    """
    Check for common header inconsistencies.
    """

    issues = []
    risk = 0

    from_header = extract_header_value(headers, "From")
    reply_to = extract_header_value(headers, "Reply-To")
    return_path = extract_header_value(headers, "Return-Path")
    message_id = extract_header_value(headers, "Message-ID")
    date_header = extract_header_value(headers, "Date")

    # ---------------------------------------------------------
    # Missing important headers
    # ---------------------------------------------------------

    if not from_header:
        issues.append("Missing From header")
        risk += 15

    if not message_id:
        issues.append("Missing Message-ID header")
        risk += 10

    if not date_header:
        issues.append("Missing Date header")
        risk += 10

    # ---------------------------------------------------------
    # Reply-To presence
    # ---------------------------------------------------------

    if reply_to and from_header:

        from_match = re.search(
            r"@([a-zA-Z0-9.-]+)",
            from_header
        )

        reply_match = re.search(
            r"@([a-zA-Z0-9.-]+)",
            reply_to
        )

        if from_match and reply_match:

            from_domain = from_match.group(1).lower()
            reply_domain = reply_match.group(1).lower()

            if from_domain != reply_domain:

                issues.append(
                    "From and Reply-To domains differ"
                )

                risk += 25

    # ---------------------------------------------------------
    # Return-Path mismatch
    # ---------------------------------------------------------

    if return_path and from_header:

        from_match = re.search(
            r"@([a-zA-Z0-9.-]+)",
            from_header
        )

        return_match = re.search(
            r"@([a-zA-Z0-9.-]+)",
            return_path
        )

        if from_match and return_match:

            from_domain = from_match.group(1).lower()
            return_domain = return_match.group(1).lower()

            if from_domain != return_domain:

                issues.append(
                    "From and Return-Path domains differ"
                )

                risk += 20

    risk = min(risk, 100)

    if risk >= 70:
        status = "HIGH"
    elif risk >= 40:
        status = "MEDIUM"
    else:
        status = "LOW"

    return {
        "status": status,
        "risk": risk,
        "issues": issues
    }


def analyze_email_headers(eml_bytes: bytes) -> dict:
    """
    Perform forensic analysis of raw email headers.
    """

    try:

        message = BytesParser(
            policy=policy.default
        ).parsebytes(eml_bytes)

    except Exception as exc:

        return {
            "status": "ERROR",
            "risk": 100,
            "error": f"Unable to parse email headers: {exc}"
        }

    headers = message

    received_headers = extract_received_headers(headers)

    all_received_text = "\n".join(
        received_headers
    )

    ip_addresses = extract_ip_addresses(
        all_received_text
    )

    consistency = analyze_header_consistency(
        headers
    )

    return {
        "status": consistency["status"],
        "risk": consistency["risk"],

        "from": extract_header_value(
            headers, "From"
        ),

        "reply_to": extract_header_value(
            headers, "Reply-To"
        ),

        "return_path": extract_header_value(
            headers, "Return-Path"
        ),

        "message_id": extract_header_value(
            headers, "Message-ID"
        ),

        "date": extract_header_value(
            headers, "Date"
        ),

        "subject": extract_header_value(
            headers, "Subject"
        ),

        "mailer": extract_header_value(
            headers, "X-Mailer"
        ),

        "received_count": len(
            received_headers
        ),

        "received_headers": received_headers,

        "source_ips": ip_addresses,

        "issues": consistency["issues"]
    }