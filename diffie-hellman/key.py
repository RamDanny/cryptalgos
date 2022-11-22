import sys
import random

sys.stdin = open('in.txt', 'r')

q = int(input())
a = int(input())

xa = random.randint(2, q)
ya = (a**xa) % q

xb = random.randint(2, q)
yb = (a**xb) % q

k1 = (yb**xa) % q
k2 = (ya**xb) % q
print(k1, k2)
