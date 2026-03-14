from email import policy
from email.parser import BytesParser


def get_email_headers(email_file):
    """
    Extract headers from an email file-like object opened in binary mode.

    Args:
        email_file: File-like object containing the raw email bytes.

    Returns:
        dict: A dictionary containing all parsed headers.
    """
    msg = BytesParser(policy=policy.default).parse(email_file)
    return dict(msg.items())
