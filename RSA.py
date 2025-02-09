from Crypto.Util.number import getPrime, GCD

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        
        x2 = x1
        x1 = x
        d = y1
        y1 = y
    
    if temp_phi == 1:
        return d + phi

def generate_keypair(bits):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p-1) * (q-1)
    e = 65537
    while GCD(e, phi) != 1:
        e = getPrime(16)
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(pubk, plaintext):
    key, n = pubk
    number = int.from_bytes(plaintext.encode('utf-8'), 'big')
    cipher = pow(number, key, n)
    return cipher

def decrypt(prk, ciphertext):
    key, n = prk
    plain = pow(ciphertext, key, n)
    numbytes = (plain.bit_length() + 7) // 8
    return plain.to_bytes(numbytes, 'big').decode('utf-8')

if __name__ == '__main__':
    public, private = generate_keypair(1024)
    message = "hello world!"
    encrypted_msg = encrypt(public, message)
    print("Encrypted:", encrypted_msg)
    decrypted_msg = decrypt(private, encrypted_msg)
    print("Decrypted:", decrypted_msg)
