import os

MSGS = [
    b"Send the final report to the dean before Friday noon.",
    b"The exam for the course starts at eight in room D9.",
    b"Lunch will be served in the cafeteria at 12:30 p.m.",
]

def random(size=16):
    return os.urandom(size)

def strxor(key, msg):
    return bytes(a ^ b for a, b in zip(key, msg))

def encrypt(key, msg):
    # check to refuse messages longer than the key
    if len(msg) > len(key):
        raise ValueError(f"Message length ({len(msg)}) exceeds key length ({len(key)}).")
    
    c = strxor(key, msg)
    print(c.hex())
    return c

def decrypt(key, c):
    return strxor(key, c)

def main():
    key = random(1024)
    print("Key (first 32 bytes):")
    print(key[:32].hex())
    print("\nCiphertexts:")
    
    ciphertexts = []
    for msg in MSGS:
        c = encrypt(key, msg)
        ciphertexts.append(c)
        
    print("\nDecrypted Plaintexts:")
    for c in ciphertexts:
        print(decrypt(key, c).decode('utf-8'))
        
    # Save ciphertexts to ciphertexts.txt
    with open("ciphertexts.txt", "w") as f:
        for c in ciphertexts:
            f.write(c.hex() + "\n")
            
    # Encrypt a 1500-byte message
    print("\nEncrypting ")
    msg_1500 = b"A" * 1500
    
    try:
        encrypt(key, msg_1500)
    except Exception as e:
        print(f"Error caught: {e}")

if __name__ == "__main__":
    main()