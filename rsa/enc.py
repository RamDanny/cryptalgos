import sys
import random

sys.stdin = open('in.txt', 'r')

def gcd(x, y):
    if y == 0:
        return x
    if x == 0:
        return y
    if x == 1 or y == 1:
        return 1
    return gcd(y, x%y)

p = int(input())
q = int(input())
n = p * q
phin = (p - 1) * (q - 1)

ea = None
while True:
    ea = random.randint(2, phin)
    if gcd(ea, phin) == 1:
        break

da = pow(ea, -1, phin)

eb = None
while True:
    eb = random.randint(2, phin)
    if gcd(eb, phin) == 1:
        break

db = pow(eb, -1, phin)


message = int(input())
ciphertext = (message ** eb) % n


message = (ciphertext ** db) % n
print(message)
