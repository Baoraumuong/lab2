"""Task 3: construct a pseudorandom pad using PyNaCl's SecretBox."""

from nacl.secret import SecretBox
from nacl.utils import random


KEY_SIZE = SecretBox.KEY_SIZE
NONCE_SIZE = SecretBox.NONCE_SIZE
TAG_SIZE = SecretBox.MACBYTES

M1 = b"Send the final report to the dean before Friday noon."
M2 = b"The exam for the course starts at eight in room D9."


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR inputs must have the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def G(key: bytes, nonce: bytes, n: int) -> bytes:
    """Return n bytes of the XSalsa20 stream after SecretBox's tag."""
    if n < 0:
        raise ValueError("pad length cannot be negative")
    tagged_pad = SecretBox(key).encrypt(bytes(n), nonce).ciphertext
    return bytes(tagged_pad[TAG_SIZE:])


def encrypt(key: bytes, message: bytes, nonce: bytes | None = None) -> bytes:
    """Return nonce || (message XOR G(key, nonce, len(message)))."""
    if nonce is None:
        nonce = random(NONCE_SIZE)
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
    return nonce + xor_bytes(message, G(key, nonce, len(message)))


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) < NONCE_SIZE:
        raise ValueError("ciphertext is too short to contain a nonce")
    nonce = ciphertext[:NONCE_SIZE]
    body = ciphertext[NONCE_SIZE:]
    return xor_bytes(body, G(key, nonce, len(body)))


def main() -> None:
    key = random(KEY_SIZE)
    nonce = random(NONCE_SIZE)
    pad = G(key, nonce, 64)
    print(f"Key: {key.hex()}")
    print(f"Nonce: {nonce.hex()}")
    print(f"G(key, nonce, 64): {pad.hex()}")

    ciphertext_1 = encrypt(key, M1)
    ciphertext_2 = encrypt(key, M1)
    print(f"First encryption of M1:  {ciphertext_1.hex()}")
    print(f"Second encryption of M1: {ciphertext_2.hex()}")
    print(f"Ciphertexts differ: {ciphertext_1 != ciphertext_2}")
    print(f"Decrypted M1: {decrypt(key, ciphertext_1).decode('utf-8')}")

    reused_nonce = random(NONCE_SIZE)
    reused_1 = encrypt(key, M1, reused_nonce)[NONCE_SIZE:]
    reused_2 = encrypt(key, M2, reused_nonce)[NONCE_SIZE:]
    overlap = min(len(reused_1), len(reused_2))
    ciphertext_xor = xor_bytes(reused_1[:overlap], reused_2[:overlap])
    plaintext_xor = xor_bytes(M1[:overlap], M2[:overlap])
    print(f"Reused nonce: {reused_nonce.hex()}")
    print(f"Reused C1 body: {reused_1.hex()}")
    print(f"Reused C2 body: {reused_2.hex()}")
    print(f"C1 XOR C2: {ciphertext_xor.hex()}")
    print(f"M1 XOR M2: {plaintext_xor.hex()}")
    print(f"C1 XOR C2 == M1 XOR M2: {ciphertext_xor == plaintext_xor}")


if __name__ == "__main__":
    main()
