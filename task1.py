"""Task 1: a one-time pad in Python 3."""

import os
from pathlib import Path


MESSAGES = (
    b"Send the final report to the dean before Friday noon.",
    b"The exam for the course starts at eight in room D9.",
    b"Lunch will be served in the main hall at half past twelve.",
)
OUTPUT_FILE = Path(__file__).with_name("ciphertexts.txt")


def random(size: int = 16) -> bytes:
    """Return cryptographically secure random bytes on every supported OS."""
    return os.urandom(size)


def strxor(left: bytes, right: bytes) -> bytes:
    """XOR equal-length byte strings."""
    if len(left) != len(right):
        raise ValueError("strxor inputs must have the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt(key: bytes, message: bytes) -> bytes:
    if len(message) > len(key):
        raise ValueError(
            f"message length {len(message)} exceeds key length {len(key)}"
        )
    return strxor(key[: len(message)], message)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return encrypt(key, ciphertext)


def main() -> None:
    key = random(1024)
    print(f"Key (first 32 of {len(key)} bytes): {key[:32].hex()}")

    ciphertexts = []
    for index, message in enumerate(MESSAGES, start=1):
        ciphertext = encrypt(key, message)
        ciphertexts.append(ciphertext)
        print(f"C{index}: {ciphertext.hex()}")

    print("Decrypted plaintexts:")
    for index, ciphertext in enumerate(ciphertexts, start=1):
        plaintext = decrypt(key, ciphertext)
        print(f"M{index}: {plaintext.decode('utf-8')}")

    OUTPUT_FILE.write_text(
        "".join(f"{ciphertext.hex()}\n" for ciphertext in ciphertexts),
        encoding="ascii",
    )
    print(f"Saved ciphertexts to {OUTPUT_FILE.name}")

    long_message = b"A" * 1500
    truncated = bytes(a ^ b for a, b in zip(key, long_message))
    print(f"Original zip-based 1500-byte ciphertext length: {len(truncated)}")
    try:
        long_ciphertext = encrypt(key, long_message)
        print(f"1500-byte ciphertext length: {len(long_ciphertext)}")
    except ValueError as error:
        print(f"1500-byte encryption refused: {error}")


if __name__ == "__main__":
    main()
