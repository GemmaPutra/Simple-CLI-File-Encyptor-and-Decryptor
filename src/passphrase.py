import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def phrase_key(_word: str, /) -> bytes:
    return base64.urlsafe_b64encode(
        PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100_000,
            length=32,
            salt=b"]\xf3:\x17\xb4\x99\xd0\x0f\x0cB@\x06o\xc8Me",  # hard coded the os.urandom() for consistencies
            backend=default_backend(),
        ).derive(bytes(_word.encode()))
    )
