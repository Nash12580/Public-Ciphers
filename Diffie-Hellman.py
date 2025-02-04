import random
import hashlib 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Params
q = int("".join([
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6",
        "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0",
        "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70",
        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0",
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708",
        "DF1FB2BC2E4A4371"
    ]), 16)

tampered_alphas = [1, q, q-1]

XA = random.randint(1, q-1)
XB = random.randint(1, q-1)

for tampered in tampered_alphas:
    print(f"\nMallory setting alpha = {tampered}")
    YA = pow(tampered, XA, q)
    YB = pow(tampered, XB, q)

    SA = pow (YB, XA, q)
    SB = pow (YA, XB, q)
    assert SA == SB, "Shared keys don't match"

    print(f"Interception Succesful: Shared Secret (s): {SA}\n")

    # Convert shared secret -> 16-byte AES key
    mallory_key = hashlib.sha256(str(SA).encode()).digest()[:16]

    print(f"Mallory's Derivced AES Key: {mallory_key.hex()}")

    iv = os.urandom(16)
    cipher = AES.new(mallory_key, AES.MODE_CBC, iv)

    m0 = b"Hi Bob"
    m1 = b"Hi Alice"

    c0 = cipher.encrypt(pad(m0, AES.block_size))
    c1 = cipher.encrypt(pad(m1, AES.block_size))

    decipher = AES.new(mallory_key, AES.MODE_CBC, iv)

    m0_decrypted = unpad(decipher.decrypt(c0), AES.block_size)
    m1_decrypted = unpad(decipher.decrypt(c1), AES.block_size)

    print(f"Alice's Encrypted Message: {c0.hex()}")
    print(f"Alice's Decrypted Message: {m1_decrypted.decode()}")
    print(f"Bob's Encrypted Message: {c1.hex()}")
    print(f"Bob's Decrypted Message: {m0_decrypted.decode()}")