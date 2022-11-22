import sys
import random

sys.stdin = open('in.txt', 'r')

message = int(input())

q = int(input())
a = int(input())

xa = random.randint(2, q)
ya = (a**xa) % q

xb = random.randint(2, q)
yb = (a**xb) % q


k = random.randint(1, q)
k1 = (yb**k) % q
c1 = (a**k) % q
c2 = (message * k1) % q


k2 = (c1**xb) % q
print(k1,k2)
message = (pow(k2, -1, q) * c2) % q
print(message)
