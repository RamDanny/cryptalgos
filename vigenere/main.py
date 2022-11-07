import sys
import random
from alpha import alphabet, alphapos, encrypt, decrypt

sys.stdin = open('in.txt', 'r')

plaintext = input()

key = ''
for i in range(3):
    key += alphabet[random.randrange(0, 26)]
print(f'Key: {key}')

ciphertext = encrypt(plaintext, key)
print(f'Ciphertext: {ciphertext}')
print(f'Plaintext: {decrypt(ciphertext, key)}')
