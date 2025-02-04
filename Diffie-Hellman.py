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