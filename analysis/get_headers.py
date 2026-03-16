from collections import defaultdict
from email import policy
from email.parser import BytesParser


def get_email_headers(email_file):
    """
    Extract email headers from a binary file-like object.

    Returns a dictionary keyed by lowercase header name, where each value is
    a list of header values. This preserves repeated headers such as Received
    and Authentication-Results and makes lookups case-insensitive.
    """
    msg = BytesParser(policy=policy.default).parse(email_file)

    headers = defaultdict(list)
    for name, value in msg.raw_items():
        headers[name.lower()].append(str(value).strip())

    return dict(headers)

    Extract useful headers from an email file-like object opened in binary mode.

    Returns:
        dict: Header mapping where repeated headers (e.g., Received) are returned as lists.
    """
    msg = BytesParser(policy=policy.default).parse(email_file)

    headers = {name: msg.get(name, "") for name in msg.keys()}
    headers["Received"] = msg.get_all("Received", [])

    return headers

