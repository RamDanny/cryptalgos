import sys
import random
from alpha import alphabet, alphapos, encrypt, decrypt

sys.stdin = open('in.txt', 'r')

plaintext = input()
key = random.randrange(0, 26)
ciphertext = encrypt(plaintext, key)
print(f'Ciphertext: {ciphertext}')
print(f'Plaintext: {decrypt(ciphertext, key)}')
