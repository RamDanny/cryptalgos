import sys
import random

sys.stdin = open('in.txt', 'r')

def h(x):
    return x % 10

def gcd(x, y):
    if y == 0:
        return x
    if x == 0:
        return y
    if x == 1 or y == 1:
        return 1
    return gcd(y, x%y)


message = int(input())

q = int(input())
a = int(input())

xa = random.randint(2, q-1)
ya = (a**xa) % q

xb = random.randint(2, q-1)
yb = (a**xb) % q

m = h(message)

k = None
while True:
    k = random.randint(1, q)
    if gcd(k, q-1) == 1:
        break

kinv = pow(k, -1, q-1)

s1 = (a**k) % q
s2 = (kinv * (m - (xa * s1))) % (q - 1)

v1 = (a**m) % q
v2 = ((ya ** s1) * (s1 ** s2)) % q

if v1 == v2:
    print('Valid sign')
else:
    print('Invalid sign')
