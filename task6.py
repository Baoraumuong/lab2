"""Task 6: a bit-oriented linear-feedback shift register."""

import secrets


MESSAGE = (
    b"From: exam-office@example.edu\n"
    b"Subject: final exam\n"
    b"Room B1-401, 8:00 on Monday."
)


class LFSR:
    def __init__(self, n: int, taps: tuple[int, ...], seed: int):
        if n <= 0:
            raise ValueError("n must be positive")
        if not 0 <= seed < (1 << n):
            raise ValueError("seed does not fit in n bits")
        if any(tap < 0 or tap >= n for tap in taps):
            raise ValueError("tap position is outside the register")
        self.n = n
        self.taps = taps
        self.tap_mask = sum(1 << tap for tap in taps)
        self.state = seed

    def next_bit(self) -> int:
        output = self.state & 1
        feedback = (self.state & self.tap_mask).bit_count() & 1
        self.state = (self.state >> 1) | (feedback << (self.n - 1))
        return output

    def generate_bits(self, count: int) -> list[int]:
        return [self.next_bit() for _ in range(count)]

    def generate_bytes(self, count: int) -> bytes:
        output = bytearray(count)
        for byte_index in range(count):
            value = 0
            for bit_index in range(8):
                value |= self.next_bit() << bit_index
            output[byte_index] = value
        return bytes(output)


def period(n: int, taps: tuple[int, ...], seed: int) -> int:
    register = LFSR(n, taps, seed)
    steps = 0
    while True:
        register.next_bit()
        steps += 1
        if register.state == seed:
            return steps


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR inputs must have the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def main() -> None:
    example = LFSR(4, (0, 1), 0b1001)
    bits = example.generate_bits(16)
    print("First 16 output bits: " + " ".join(map(str, bits)))

    cases = (
        (4, (0, 1), 0b1001),
        (16, (0, 2, 3, 5), 1),
        (16, (0, 8), 1),
    )
    for n, taps, seed in cases:
        print(f"Period n={n}, taps={set(taps)}, seed={seed}: {period(n, taps, seed)}")

    seed = secrets.randbits(32)
    while seed == 0:
        seed = secrets.randbits(32)
    pad = LFSR(32, (0, 10, 30, 31), seed).generate_bytes(len(MESSAGE))
    ciphertext = xor_bytes(MESSAGE, pad)
    sample = LFSR(32, (0, 10, 30, 31), seed).generate_bytes(64 * 1024)
    ones_fraction = sum(byte.bit_count() for byte in sample) / (len(sample) * 8)
    print(f"Seed: {seed:08x}")
    print(f"Pad: {pad.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Fraction of 1-bits in 64 KiB: {ones_fraction:.8f}")


if __name__ == "__main__":
    main()
