alphabet = 'abcdefghijklmnopqrstuvwxyz'
alphapos = dict()
for i in range(26):
    alphapos[alphabet[i]] = i

def encrypt(plaintext, key):
    ciphertext = ''
    k = 0
    for c in plaintext:
        ciphertext += alphabet[(alphapos[c] + alphapos[key[k]]) % len(alphabet)]
        k = (k + 1) % len(key)
    return ciphertext

def decrypt(ciphertext, key):
    plaintext = ''
    k = 0
    for c in ciphertext:
        plaintext += alphabet[(alphapos[c] + 26 - alphapos[key[k]]) % len(alphabet)]
        k = (k + 1) % len(key)
    return plaintext

