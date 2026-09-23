M1 = b"Send the final report to the dean before Friday noon."
M2 = b"The exam for the course starts at eight in room D9."

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def load_ciphertexts(filename="ciphertexts.txt"):
    with open(filename, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    return [bytes.fromhex(line) for line in lines]


def crib_drag(xored, crib=b" the "):
    print("\nCrib dragging:")
    for pos in range(len(xored) - len(crib) + 1):
        part = xored[pos:pos + len(crib)]
        result = xor_bytes(part, crib)
        if all((ord('a') <= b <= ord('z')) or b == ord(' ') for b in result):
            print(f"Position {pos:2d}: {result.decode('ascii')}")

def main():
    ciphertexts = load_ciphertexts()
    c1 = ciphertexts[0]
    c2 = ciphertexts[1]
    c1_xor_c2 = xor_bytes(c1, c2)
    print("C1 XOR C2 = " + c1_xor_c2.hex())

    m1_xor_m2 = xor_bytes(M1, M2)
    print("\nM1 XOR M2 = " + m1_xor_m2.hex())
    print("\nC1 XOR C2 == M1 XOR M2 ? " + str(c1_xor_c2 == m1_xor_m2))

    crib_drag(c1_xor_c2)
    target = b"Nothing to see here."
    target_padded = target.ljust(len(c1), b' ')
    key = xor_bytes(c1, target_padded)
    print("\nFake key k':")
    print(key.hex())

    decrypt = xor_bytes(c1, key)
    print("\nDecrypt with k':")
    print(repr(decrypt.decode("ascii")))

    print("\nCheck:" + str(decrypt == target_padded))

if __name__ == "__main__":
    main()