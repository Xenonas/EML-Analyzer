import hashlib

def get_sha256(file):
    """
    Calculate the SHA256 hash of a given file.

    Args:
        file (File): The file for which to calculate the hash.
    Returns:
        str: The SHA256 hash of the file.
    """

    sha256_hash = hashlib.sha256()
    for byte_block in iter(lambda: file.read(4096), b""):
        sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()