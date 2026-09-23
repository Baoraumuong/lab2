"""Task 7: recover an LFSR seed and plaintext from known plaintext."""

from task6 import LFSR, xor_bytes


CIPHERTEXT = bytes.fromhex(
    "3d5cae3331120fe78d2359b8998d846d5230dc78741f3880d0e36e3fb4659796"
    "4a5841c015c4e29f25bbdcb0f946993cd2af3984176325a9688ab8ab6d07dfda"
    "f2f680eee88923ccc31738ce4c3c9962a5b92873b3064e64a69054def9c71331"
)
KNOWN_PREFIX = b"From: ex"
KNOWN_TAPS = (0, 10, 30, 31)


def bits_lsb_first(data: bytes) -> list[int]:
    return [(byte >> bit) & 1 for byte in data for bit in range(8)]


def recover_seed(ciphertext: bytes, known_plaintext: bytes) -> int:
    known_keystream = xor_bytes(ciphertext[:4], known_plaintext[:4])
    return int.from_bytes(known_keystream, "little")


def decrypt_with_register(ciphertext: bytes, seed: int, taps: tuple[int, ...]) -> bytes:
    pad = LFSR(32, taps, seed).generate_bytes(len(ciphertext))
    return xor_bytes(ciphertext, pad)


def berlekamp_massey(sequence: list[int]) -> tuple[int, list[int]]:
    """Return the shortest binary recurrence length and coefficients."""
    c = [0] * (len(sequence) + 1)
    previous = [0] * (len(sequence) + 1)
    c[0] = previous[0] = 1
    length = 0
    shift = 1
    for index in range(len(sequence)):
        discrepancy = sequence[index]
        for offset in range(1, length + 1):
            discrepancy ^= c[offset] & sequence[index - offset]
        if discrepancy == 0:
            shift += 1
            continue
        old_c = c.copy()
        for offset in range(len(sequence) + 1 - shift):
            c[offset + shift] ^= previous[offset]
        if 2 * length <= index:
            length = index + 1 - length
            previous = old_c
            shift = 1
        else:
            shift += 1
    return length, c[1 : length + 1]


def recurrence_to_taps(length: int, coefficients: list[int]) -> tuple[int, ...]:
    # sequence[k] = XOR(coeff[i-1] * sequence[k-i]); a delay i
    # corresponds to register tap position length-i.
    return tuple(
        length - delay
        for delay, enabled in enumerate(coefficients, start=1)
        if enabled
    )


def main() -> None:
    seed = recover_seed(CIPHERTEXT, KNOWN_PREFIX)
    plaintext = decrypt_with_register(CIPHERTEXT, seed, KNOWN_TAPS)
    print(f"Recovered seed: {seed:08x}")
    print("Recovered message:")
    print(plaintext.decode("utf-8"))

    known_stream = xor_bytes(CIPHERTEXT[: len(KNOWN_PREFIX)], KNOWN_PREFIX)
    length, coefficients = berlekamp_massey(bits_lsb_first(known_stream))
    recovered_taps = recurrence_to_taps(length, coefficients)
    bonus_plaintext = decrypt_with_register(CIPHERTEXT, seed, recovered_taps)
    print(f"Bonus recovered register length: {length}")
    print(f"Bonus recovered taps: {set(recovered_taps)}")
    print(f"Bonus message matches: {bonus_plaintext == plaintext}")


if __name__ == "__main__":
    main()
