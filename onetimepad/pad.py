def encrypt(plaintext, key):
    ciphertext = ''
    for i in range(len(key)):
        ciphertext += str(int(plaintext[i]) ^ int(key[i]))
    return ciphertext

def decrypt(ciphertext, key):
    plaintext = ''
    for i in range(len(key)):
        plaintext += str(int(ciphertext[i]) ^ int(key[i]))
    return plaintext

