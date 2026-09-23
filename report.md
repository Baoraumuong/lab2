# Lab 02 - From the One-Time Pad to Stream Ciphers

The programs were run with Python 3.11.5. PyNaCl 1.6.2 was used for Tasks
3-5. Values generated randomly will be different on another run.

## Task 1 - One-time pad

Program: `task1.py` (`task01.py` is retained as a compatibility entry point).

### Output

```text
Key (first 32 of 1024 bytes): 9597ad45a92fa798cf26f25ac29b6c28bb5f4308e29bb54cef51978c665e351e
C1: c6f2c321895bcffdef409b34a3f74c5ade2f2c7a96bbc123cf25ffe9463a507f68691fa1dc3a56c82b3d6826c6e811224e5ad358fe
C2: c1ffc865cc57c6f5ef409d28e2ef044d9b3c2c7d90e8d06c9c25f6fe122d157f726918addd3d508d62153a3dcde60522640c92
C3: d9e2c326c10fd0f1a34ad238a7bb1f4dc929266cc2f2db6c9b39f2ac0b3f5c7026211ca8d67545d92b137b23c4a9186353419c42a7631c9e0ac7
Decrypted plaintexts:
M1: Send the final report to the dean before Friday noon.
M2: The exam for the course starts at eight in room D9.
M3: Lunch will be served in the main hall at half past twelve.
Saved ciphertexts to ciphertexts.txt
Original zip-based 1500-byte ciphertext length: 1024
1500-byte encryption refused: message length 1500 exceeds key length 1024
```

### Explanation

The original `open("/dev/urandom").read(size)` fails on Windows with
`FileNotFoundError` because Windows has no `/dev/urandom`. On a Unix-like
system, Python 3 also opens the device in text mode by default and tries to
decode random bytes, which can produce `UnicodeDecodeError`. Opening it as
`"rb"` fixes the Python 3 text/binary issue, while `os.urandom(size)` is
portable and uses the operating system's secure random source.

The original XOR loop was based on `zip(key, message)`. `zip` stops when its
shortest input ends, so a 1500-byte message and 1024-byte key silently produce
only 1024 ciphertext bytes; the last 476 plaintext bytes are never encrypted.
The final `encrypt` checks the lengths first and refuses this operation instead
of silently losing data.

## Task 2 - Reusing the pad

Program: `task2.py`. It reads only the three hex lines in `ciphertexts.txt`.

### Output

```text
C1 XOR C2: 070d0b44450c09080000061c41184817451300070653114f53000917541745001a00070c010706454928521b0b0e14002a5641
M1 XOR M2: 070d0b44450c09080000061c41184817451300070653114f53000917541745001a00070c010706454928521b0b0e14002a5641
C1 XOR C2 == M1 XOR M2: True
Crib-dragging b' the ':
position  4: 'exam '
position  8: ' tnya'
position 12: 'al re'
position 24: 'start'
Fake key k': 889db749e035a8dd9b2fbb47c6926c32bb5d4954b69be103ef05dfc9661a705f48493f81fc1a76e80b1d4806e6c831026e7af378de
C1 decrypted under k': 'Nothing to see here.                                 '
Forgery check: True
```

### Explanation

With one reused pad `K`, `C1 = M1 XOR K` and `C2 = M2 XOR K`. Therefore

```text
C1 XOR C2 = M1 XOR K XOR M2 XOR K = M1 XOR M2,
```

because each key bit is XORed twice and cancels. This is why the key
disappears in step 1.

Crib dragging assumes that `" the "` occurs at a chosen position in one
message. At position 4 it really occurs in M1, so XORing the crib with the
corresponding part of `M1 XOR M2` reveals `"exam "` from M2. At position 24,
the crib aligns with M2 and reveals `"start"` from M1. Results such as
`" tnya"` and `"al re"` only pass the simple lowercase-and-space filter by
chance; the filter tests character shape, not whether a phrase is meaningful.

For every chosen plaintext `P` of the right length, an apparent key
`K' = C1 XOR P` exists. The constructed `K'` consequently makes C1 decrypt to
`"Nothing to see here."` followed by spaces. An attacker who sees only C1
cannot distinguish that plaintext/key pair from the genuine pair. Perfect
secrecy without authentication also provides no proof of which plaintext was
intended.

## Task 3 - A pseudorandom pad from NaCl

Program: `task3.py` (`task03.py` is retained as a compatibility entry point).
`G` encrypts `bytes(n)` with a supplied nonce and removes the first 16-byte
Poly1305 tag from `.ciphertext`, leaving the `n` XSalsa20 stream bytes.

### Output

```text
Key: c76bdbc6bb14e0c8792bf088d27f5d4ba370c0195c1fe5f7104a2de1b036b264
Nonce: c4f86d1807156a737a5ecba1acda561684d5eba83214f3a9
G(key, nonce, 64): 2958adb504860d460d6344682fe000ee22c2f9b2636351bfc47146bf1a22f3ba88529d77c398be9a8a81d488c18b8222219ac99239b9b9c6c1d524eb3d350bf4
First encryption of M1:  bf8b185d85343fbcf9f78e49840e560cc6f35f171557a1d336b901e6eaf2176df54ef3afdd5abb87bf579ebfa3860748991e7ffac45cff579f377378aad3ba56aad1b4a90a1581100f6f1f42cb
Second encryption of M1: a43448676c7fc3191a483405cc5bc057e89e954d93fc84dfa775ef2340749bdc7399c41214a51feeb26293829a9156ccd07804fc3d849b507a895ab7e0f6a4573959826698390d26f15e737550
Ciphertexts differ: True
Decrypted M1: Send the final report to the dean before Friday noon.
Reused nonce: 8450184cb183d89b5f263243a502e8d390612fc60d8f703a
Reused C1 body: 6c534f718168a7ec574daa68918066199cd4487b1971fad576cdf71c72dbaa816ea2a42e055ab209d0f1166a873ca0a212f45108d7
Reused C2 body: 6b5e4435c464aee4574dac74d0982e0ed9c7487c1f22eb9a25cdfe0b26ccef8174a2a322045db44c99d944718c32b4a238a210
C1 XOR C2: 070d0b44450c09080000061c41184817451300070653114f53000917541745001a00070c010706454928521b0b0e14002a5641
M1 XOR M2: 070d0b44450c09080000061c41184817451300070653114f53000917541745001a00070c010706454928521b0b0e14002a5641
C1 XOR C2 == M1 XOR M2: True
```

### Explanation

The two normal encryptions of M1 use fresh 24-byte nonces. A nonce changes the
input to `G`, so each encryption gets a different pseudorandom pad even though
the key and plaintext are identical. The nonce is public and is included at
the start of the ciphertext, but it must be unique for a given key.

Reusing a nonce with the same key reproduces the same pad. XORing the two
ciphertext bodies cancels that pad and exposes `M1 XOR M2`, exactly as in Task
2. Known or guessed parts of either plaintext then reveal the matching parts
of the other.

## Task 4 - Encrypting a book

Program: `task4.py`. It processes the book in 1 MiB chunks. A nonce is the
random 16-byte file prefix followed by an 8-byte, big-endian chunk counter.
The decrypted PDF was also parsed successfully by a PDF reader as 1,130 pages.

### Output

```text
Key: b76365a63297204b1c8db4e0ab1baa58122cfc6a9ca2c7b15f97f0623e56de36
Nonce prefix: 3e981feb05194de98a7794551c10d805
book.pdf size: 9110736 bytes
book.enc size: 9110752 bytes
First 16 plaintext bytes:  255044462d312e350a25d0d4c5d80a38
First 16 ciphertext bytes: d4e21df5bbe0d571355889bc820d00b4
SHA-256 book.pdf:     67bc4507f7558c99f0ecc331651da224f0a73b2453fdd8ff5e67c8d4e56cc7dd
SHA-256 book.dec.pdf: 67bc4507f7558c99f0ecc331651da224f0a73b2453fdd8ff5e67c8d4e56cc7dd
Hashes match: True
Encryption time: 0.068475 seconds
Normal C0 XOR C1 == M0 XOR M1: False
Forgotten-counter C0 XOR C1 == M0 XOR M1: True
Buggy decrypt hash matches original: True
book.dec.pdf parsed successfully: 1130 pages
```

### Explanation

The key is only 32 bytes, whereas this book is 9,110,736 bytes (about 8.69
MiB). XSalsa20 expands the short key plus each nonce into as much pad as the
chunk needs; unlike an OTP, the complete pad does not have to be stored.

`book.enc` is exactly 16 bytes longer than `book.pdf` because it stores one
16-byte random prefix at the beginning. The encrypted chunk bodies have the
same lengths as the plaintext chunks. The counter is reconstructed from the
chunk position, and this exercise deliberately discards SecretBox's per-chunk
16-byte tags, so no other bytes are added.

With the counter, chunks 0 and 1 use distinct nonces and pads, and the XOR
equality is false. When every nonce is `prefix || 0`, every full chunk is
encrypted with the same pad. Then `C0 XOR C1 = M0 XOR M1`, leaking relations
between every pair of corresponding chunk positions. Buggy decryption still
opens the book because it repeats the same mistake: applying the same repeated
pad a second time cancels it. Correct round-trip behavior does not imply
security.

## Task 5 - Changing an encrypted amount

Program: `task5.py`.

### Output

```text
Key: c98616274192400a7fc15309cc77f860a43032e4934c4d88d30a02463e8d21b9
Task 3 pad: 1d93b10a6b02293cfa9ed14e101a6f0b
Task 3 ciphertext: 3f44977a325539ae12a8fa9e77734ed4c296d4bed9dd321b4dd2e82a294d6b1ccaafe17e304f3c4f
Forged ciphertext: 3f44977a325539ae12a8fa9e77734ed4c296d4bed9dd321b4dd2e82a294d6b1cc3a7e17e304f3c4f
Forged decryption: PAY BOB 9900 USD
SecretBox ciphertext: c81c4fe2fc6c229b577bd53d64e228c26fd11368637f47d4795d28e766a157edb0f796ab0316f8e7dc184cec43d79e9d740c78b6b3e61c46
Forged SecretBox ciphertext: c81c4fe2fc6c229b577bd53d64e228c26fd11368637f47d4795d28e766a157edb0f796ab0316f8e7dc184cec43d79e9d7d0478b6b3e61c46
SecretBox forged decryption: CryptoError: Decryption failed. Ciphertext failed verification
```

### Explanation

The Task 3 cipher has no authentication. If `C = M XOR P`, changing its body
to `C' = C XOR M XOR M'` makes decryption produce
`C' XOR P = M'`. The attack needs the known original and desired text but not
the key or pad. Here the delta changes `0100` to `9900`.

Real SecretBox places a 16-byte Poly1305 authentication tag between its nonce
and encrypted body. The tag binds the ciphertext to the secret key. Changing
the body without recomputing a valid tag makes verification fail, so
`box.decrypt` raises `CryptoError` and releases no forged plaintext. The tag
adds integrity and authenticity, which plain stream encryption lacks.

## Task 6 - A shift-register generator

Program: `task6.py`. Output bits are packed bit 0 first, so the example's first
eight output bits form `0x59`.

### Output

```text
First 16 output bits: 1 0 0 1 1 0 1 0 1 1 1 1 0 0 0 1
Period n=4, taps={0, 1}, seed=9: 15
Period n=16, taps={0, 2, 3, 5}, seed=1: 65535
Period n=16, taps={0, 8}, seed=1: 24
Seed: cfefacb6
Pad: b6acefcfa91c84fa54e48894a2f7b9c99f5eaecf6e3cdf2a3b3507ccfc0abc1092ba65e792a0292dfef8e0b02d40ef5324e593b3f26dd22fa35e685ae79a3f4d00470fef9d811158243701eb1591
Ciphertext: f0de80a2933ce1823589a5fbc491d0aafa1ecbb70f51af465e1b62a88900ef65f0d00084e69a094b979681dc0d25973249efc1dc9d00f26d92735c6ad6b61f753a773fcff2ef31154b59658a6cbf
Fraction of 1-bits in 64 KiB: 0.49870682
```

### Explanation

The seed must not be zero because every tapped bit of the all-zero state is
zero. Its feedback is therefore zero forever, its period is 1, and it emits an
all-zero pad that leaves the plaintext unchanged.

The taps `{0, 8}` return this nonzero seed after only 24 steps, or three bytes,
instead of approaching the maximum nonzero 16-bit period of 65,535. Thus the
pad repeats every three bytes. Ciphertext sections at the same position in
different periods have been XORed with identical pad bytes; XORing those
sections cancels the pad just as in Task 2. A roughly 50% one-bit frequency
does not compensate for this short, predictable period.

## Task 7 - Breaking the shift register

Program: `task7.py`. The bonus uses Berlekamp-Massey over GF(2), so it does not
assume the taps.

### Output

```text
Recovered seed: 5ec12e7b
Recovered message:
From: exam-office@example.edu
Subject: Lab 02
Flag: a pad that looks random is not a random pad.
Bonus recovered register length: 32
Bonus recovered taps: {0, 10, 30, 31}
Bonus message matches: True
```

### Explanation

Known plaintext reveals keystream because `P XOR C = pad`. During the first 32
steps, the LFSR outputs the 32 seed bits directly from right to left. Thus four
known bytes are already sufficient to reconstruct this 32-bit state when the
size, taps, and bit order are known; the supplied eight known bytes provide 64
keystream bits, enough to recover the seed and validate/predict the recurrence.
The stream may look random statistically, but it is a deterministic linear
function of only 32 secret state bits.

Without the taps, 64 consecutive known keystream bits are also enough for
Berlekamp-Massey to recover a linear recurrence of length 32. Converting that
recurrence back to this register convention yields `{0, 10, 30, 31}`, after
which the remainder decrypts normally.

A 256-bit LFSR would increase the amount of known keystream needed, but would
still not be cryptographically safe. With known taps, 256 known output bits
(32 bytes) expose its state. With unknown taps, about 512 consecutive output
bits are generally enough to recover its linear recurrence using
Berlekamp-Massey. Secure stream ciphers require nonlinear, cryptographically
designed state evolution, not merely a larger linear register.
