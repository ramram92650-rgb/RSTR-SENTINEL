def analyze_sender(sender: str, reply_to: str | None = None) -> dict:

    sender = sender.strip().lower()
    reply_to = (reply_to or "").strip().lower()

    if not reply_to:
        return {
            "mismatch": False,
            "sender": sender,
            "reply_to": None,
            "sender_domain": extract_domain(sender),
            "reply_to_domain": None,
            "risk": 0,
            "reason": "No Reply-To address provided"
        }

    sender_domain = extract_domain(sender)
    reply_to_domain = extract_domain(reply_to)

    if not sender_domain or not reply_to_domain:
        return {
            "mismatch": True,
            "sender": sender,
            "reply_to": reply_to,
            "sender_domain": sender_domain,
            "reply_to_domain": reply_to_domain,
            "risk": 30,
            "reason": "Invalid sender or Reply-To address"
        }

    if sender_domain != reply_to_domain:
        return {
            "mismatch": True,
            "sender": sender,
            "reply_to": reply_to,
            "sender_domain": sender_domain,
            "reply_to_domain": reply_to_domain,
            "risk": 35,
            "reason": "Sender and Reply-To domains do not match"
        }

    return {
        "mismatch": False,
        "sender": sender,
        "reply_to": reply_to,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "risk": 0,
        "reason": "Sender and Reply-To domains match"
    }


def extract_domain(email: str) -> str:

    if "@" not in email:
        return ""

    return email.split("@")[-1].strip().lower()