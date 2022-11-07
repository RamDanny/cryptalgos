alphabet = 'abcdefghijklmnopqrstuvwxyz'
alphapos = dict()
for i in range(26):
    alphapos[alphabet[i]] = i

def encrypt(plaintext, key):
    ciphertext = ''
    for c in plaintext:
        ciphertext += alphabet[(alphapos[c] + key) % len(alphabet)]
    return ciphertext

def decrypt(ciphertext, key):
    plaintext = ''
    for c in ciphertext:
        plaintext += alphabet[(alphapos[c] + 26 - key) % len(alphabet)]
    return plaintext

