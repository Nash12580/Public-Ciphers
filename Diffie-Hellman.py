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


alpha = int("".join([
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F",
        "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213",
        "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1",
        "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A",
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24",
        "855E6EEB22B3B2E5"
    ]), 16)

XA = random.randint(1, q-1)
XB = random.randint(1, q-1)

YA = pow(alpha, XA, q)
YB = pow(alpha, XB, q)

SA = pow (YB, XA, q)
SB = pow (YA, XB, q)

assert SA == SB, "Shared keys don't match"

# Convert shared secret -> 16-byte AES key
k = hashlib.sha256(str(SA).encode()).digest()[:16]

iv = os.urandom(16)
cipher = AES.new(k, AES.MODE_CBC, iv)

m0 = b"Hi Bob"
m1 = b"Hi Alice"

c0 = cipher.encrypt(pad(m0, AES.block_size))
c1 = cipher.encrypt(pad(m1, AES.block_size))

decipher = AES.new(k, AES.MODE_CBC, iv)

m0_decrypted = unpad(decipher.decrypt(c0), AES.block_size)
m1_decrypted = unpad(decipher.decrypt(c1), AES.block_size)

print(f"Alice's Encrypted Message: {c0.hex()}")
print(f"Alice's Decrypted Message: {m1_decrypted.decode()}")
print(f"Bob's Encrypted Message: {c1.hex()}")
print(f"Bob's Decrypted Message: {m0_decrypted.decode()}")