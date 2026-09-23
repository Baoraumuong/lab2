"""Task 5: ciphertext malleability with and without authentication."""

from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.utils import random

from task3 import G, NONCE_SIZE, decrypt, encrypt, xor_bytes


ORIGINAL = b"PAY BOB 0100 USD"
FORGED = b"PAY BOB 9900 USD"


def alter_body(ciphertext: bytes, offset: int) -> bytes:
    difference = xor_bytes(ORIGINAL, FORGED)
    prefix = ciphertext[:offset]
    body = ciphertext[offset:]
    return prefix + xor_bytes(body, difference)


def main() -> None:
    key = random(SecretBox.KEY_SIZE)
    print(f"Key: {key.hex()}")

    ciphertext = encrypt(key, ORIGINAL)
    forged_ciphertext = alter_body(ciphertext, NONCE_SIZE)
    nonce = ciphertext[:NONCE_SIZE]
    print(f"Task 3 pad: {G(key, nonce, len(ORIGINAL)).hex()}")
    print(f"Task 3 ciphertext: {ciphertext.hex()}")
    print(f"Forged ciphertext: {forged_ciphertext.hex()}")
    print(f"Forged decryption: {decrypt(key, forged_ciphertext).decode('ascii')}")

    box = SecretBox(key)
    authenticated = bytes(box.encrypt(ORIGINAL))
    authenticated_forgery = alter_body(
        authenticated, SecretBox.NONCE_SIZE + SecretBox.MACBYTES
    )
    print(f"SecretBox ciphertext: {authenticated.hex()}")
    print(f"Forged SecretBox ciphertext: {authenticated_forgery.hex()}")
    try:
        result = box.decrypt(authenticated_forgery)
        print(f"SecretBox forged decryption: {result!r}")
    except CryptoError as error:
        print(f"SecretBox forged decryption: {type(error).__name__}: {error}")


if __name__ == "__main__":
    main()
