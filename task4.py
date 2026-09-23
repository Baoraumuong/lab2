"""Task 4: encrypt a PDF in independently-nonced 1 MiB chunks."""

import hashlib
import os
import time
from pathlib import Path

from nacl.secret import SecretBox
from nacl.utils import random


CHUNK_SIZE = 1024 * 1024
PREFIX_SIZE = 16
TAG_SIZE = SecretBox.MACBYTES
HERE = Path(__file__).parent
BOOK = HERE / "book.pdf"
ENCRYPTED = HERE / "book.enc"
DECRYPTED = HERE / "book.dec.pdf"
BUGGY_ENCRYPTED = HERE / "book-buggy.enc"
BUGGY_DECRYPTED = HERE / "book-buggy.dec.pdf"


def G(key: bytes, nonce: bytes, length: int) -> bytes:
    tagged_pad = SecretBox(key).encrypt(bytes(length), nonce).ciphertext
    return bytes(tagged_pad[TAG_SIZE:])


def xor_fast(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR inputs must have the same length")
    if not left:
        return b""
    value = int.from_bytes(left, "little") ^ int.from_bytes(right, "little")
    return value.to_bytes(len(left), "little")


def chunk_nonce(prefix: bytes, index: int, use_counter: bool) -> bytes:
    counter = index if use_counter else 0
    return prefix + counter.to_bytes(8, "big")


def encrypt_file(
    source: Path,
    destination: Path,
    key: bytes,
    prefix: bytes,
    *,
    use_counter: bool,
) -> None:
    with source.open("rb") as source_file, destination.open("wb") as output:
        output.write(prefix)
        index = 0
        while chunk := source_file.read(CHUNK_SIZE):
            nonce = chunk_nonce(prefix, index, use_counter)
            output.write(xor_fast(chunk, G(key, nonce, len(chunk))))
            index += 1


def decrypt_file(
    source: Path, destination: Path, key: bytes, *, use_counter: bool
) -> None:
    with source.open("rb") as source_file, destination.open("wb") as output:
        prefix = source_file.read(PREFIX_SIZE)
        if len(prefix) != PREFIX_SIZE:
            raise ValueError("encrypted file does not contain a complete prefix")
        index = 0
        while chunk := source_file.read(CHUNK_SIZE):
            nonce = chunk_nonce(prefix, index, use_counter)
            output.write(xor_fast(chunk, G(key, nonce, len(chunk))))
            index += 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def chunk_xor_equality(plaintext: Path, ciphertext: Path) -> bool:
    with plaintext.open("rb") as plain, ciphertext.open("rb") as encrypted:
        encrypted.seek(PREFIX_SIZE)
        m0 = plain.read(CHUNK_SIZE)
        m1 = plain.read(CHUNK_SIZE)
        c0 = encrypted.read(CHUNK_SIZE)
        c1 = encrypted.read(CHUNK_SIZE)
    if not m1 or len(m0) != len(m1) or len(c0) != len(c1):
        raise ValueError("the comparison needs two complete, equal-sized chunks")
    return xor_fast(c0, c1) == xor_fast(m0, m1)


def main() -> None:
    if not BOOK.exists():
        raise FileNotFoundError(
            "book.pdf is missing; download https://toc.cryptobook.us/book.pdf"
        )

    key = random(SecretBox.KEY_SIZE)
    prefix = random(PREFIX_SIZE)
    print(f"Key: {key.hex()}")
    print(f"Nonce prefix: {prefix.hex()}")

    start = time.perf_counter()
    encrypt_file(BOOK, ENCRYPTED, key, prefix, use_counter=True)
    encryption_seconds = time.perf_counter() - start
    decrypt_file(ENCRYPTED, DECRYPTED, key, use_counter=True)

    with BOOK.open("rb") as plaintext, ENCRYPTED.open("rb") as ciphertext:
        first_plaintext = plaintext.read(16)
        ciphertext.seek(PREFIX_SIZE)
        first_ciphertext = ciphertext.read(16)

    source_hash = sha256_file(BOOK)
    decrypted_hash = sha256_file(DECRYPTED)
    print(f"book.pdf size: {os.path.getsize(BOOK)} bytes")
    print(f"book.enc size: {os.path.getsize(ENCRYPTED)} bytes")
    print(f"First 16 plaintext bytes:  {first_plaintext.hex()}")
    print(f"First 16 ciphertext bytes: {first_ciphertext.hex()}")
    print(f"SHA-256 book.pdf:     {source_hash}")
    print(f"SHA-256 book.dec.pdf: {decrypted_hash}")
    print(f"Hashes match: {source_hash == decrypted_hash}")
    print(f"Encryption time: {encryption_seconds:.6f} seconds")

    normal_equal = chunk_xor_equality(BOOK, ENCRYPTED)
    buggy_prefix = random(PREFIX_SIZE)
    encrypt_file(
        BOOK, BUGGY_ENCRYPTED, key, buggy_prefix, use_counter=False
    )
    decrypt_file(
        BUGGY_ENCRYPTED, BUGGY_DECRYPTED, key, use_counter=False
    )
    buggy_equal = chunk_xor_equality(BOOK, BUGGY_ENCRYPTED)
    buggy_hash = sha256_file(BUGGY_DECRYPTED)
    print(f"Normal C0 XOR C1 == M0 XOR M1: {normal_equal}")
    print(f"Forgotten-counter C0 XOR C1 == M0 XOR M1: {buggy_equal}")
    print(f"Buggy decrypt hash matches original: {buggy_hash == source_hash}")


if __name__ == "__main__":
    main()
