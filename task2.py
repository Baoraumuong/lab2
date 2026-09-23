"""Task 2: demonstrate the consequences of reusing a one-time pad."""

from pathlib import Path

from task1 import MESSAGES, strxor


CIPHERTEXT_FILE = Path(__file__).with_name("ciphertexts.txt")
CRIB = b" the "
FORGED_MESSAGE = b"Nothing to see here."


def xor_prefix(left: bytes, right: bytes) -> bytes:
    length = min(len(left), len(right))
    return strxor(left[:length], right[:length])


def load_ciphertexts() -> list[bytes]:
    lines = CIPHERTEXT_FILE.read_text(encoding="ascii").splitlines()
    if len(lines) < 3:
        raise ValueError("ciphertexts.txt must contain three ciphertexts")
    return [bytes.fromhex(line) for line in lines[:3]]


def main() -> None:
    ciphertexts = load_ciphertexts()
    c1_xor_c2 = xor_prefix(ciphertexts[0], ciphertexts[1])
    m1_xor_m2 = xor_prefix(MESSAGES[0], MESSAGES[1])
    print(f"C1 XOR C2: {c1_xor_c2.hex()}")
    print(f"M1 XOR M2: {m1_xor_m2.hex()}")
    print(f"C1 XOR C2 == M1 XOR M2: {c1_xor_c2 == m1_xor_m2}")

    print(f"Crib-dragging {CRIB!r}:")
    for position in range(len(c1_xor_c2) - len(CRIB) + 1):
        candidate = strxor(
            c1_xor_c2[position : position + len(CRIB)], CRIB
        )
        if all(byte == 0x20 or 0x61 <= byte <= 0x7A for byte in candidate):
            print(f"position {position:2}: {candidate.decode('ascii')!r}")

    desired = FORGED_MESSAGE.ljust(len(ciphertexts[0]), b" ")
    fake_key = strxor(ciphertexts[0], desired)
    check = strxor(ciphertexts[0], fake_key)
    print(f"Fake key k': {fake_key.hex()}")
    print(f"C1 decrypted under k': {check.decode('ascii')!r}")
    print(f"Forgery check: {check == desired}")


if __name__ == "__main__":
    main()
