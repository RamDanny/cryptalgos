import sys
import random
from pad import encrypt, decrypt

sys.stdin = open('in.txt', 'r')

plaintext = input()

key = ''
for i in range(len(plaintext)):
    key += str(random.randrange(0, 2))
print(f'Key: {key}')

ciphertext = encrypt(plaintext, key)
print(f'Ciphertext: {ciphertext}')
print(f'Plaintext: {decrypt(ciphertext, key)}')
