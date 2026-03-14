import email


def get_email_headers(email_file):
    """
    Extracts email headers from a given email file.

    Args:
        email_file (str): The path to the email file.
    Returns:
        dict: A dictionary containing the email headers.
    """
    with open(email_file, 'r') as f:
        msg = email.message_from_file(f)

    headers = {}
    for header in msg.keys():
        headers[header] = msg[header]
    print(headers)
    return headers