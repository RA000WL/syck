"""syck parity fixture: base64-encoded credential for the decoder path."""

import base64

# Encoded at rest; decoded by the scanner's base64 stage.
ENCODED_AWS_SECRET = "QVdTX1NFQ1JFVF9BQ0NFU1NfS0VZPXdKYWxyWFV0bkZFTUkvSzdNREVORy9iUHhSZmlDWUVYQU1QTEVLRVk="


def load_key() -> str:
    return base64.b64decode(ENCODED_AWS_SECRET).decode()


if __name__ == "__main__":
    print(load_key())
