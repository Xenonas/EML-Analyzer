from email import policy
from email.parser import BytesParser


def get_email_headers(email_file):
    """
    Extract useful headers from an email file-like object opened in binary mode.

    Returns:
        dict: Header mapping where repeated headers (e.g., Received) are returned as lists.
    """
    msg = BytesParser(policy=policy.default).parse(email_file)

    headers = {name: msg.get(name, "") for name in msg.keys()}
    headers["Received"] = msg.get_all("Received", [])

    return headers
