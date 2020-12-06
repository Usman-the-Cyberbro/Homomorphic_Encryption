import random
import sys
import math
import time

start_time = time.time()


def ipow(x, y, n):
    A = x = x % n
    yield A
    t = 1
    while t <= y:
        t <<= 1

    t >>= 2

    while t:
        A = (A * A) % n
        if t & y:
            A = (A * x) % n
        yield A
        t >>= 1


def default_k(bits):
    return max(64, 2 * bits)


def rabin_miller_primality_test(test, possible):
    return 1 not in ipow(test, possible - 1, possible)


def is_prime(possible, k=None):
    initialprimes = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
                     47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97)
    if k is None:
        k = default_k(possible.bit_length())
    for i in initialprimes:
        if possible % i == 0:
            return False
    for i in range(int(k)):
        test = random.randrange(2, possible) | 1
        if rabin_miller_primality_test(test, possible):
            return False
    return True


def generate_prime(bits, k=None):
    assert bits >= 8
    if k is None:
        k = default_k(bits)
    while True:
        possible = random.randrange(2 ** (bits - 1) + 1, 2 ** bits) | 1
        if is_prime(possible, k):
            return possible


def inversemod(x, p):
    d = 1
    r = x
    while 1:
        d = ((p // r + 1) * d) % p
        r = (d * x) % p
        if r == 1:
            break
    else:
        print("Error")
    return d


class PublicKey(object):
    def __init__(self, bits, n):
        self.bits = bits
        self.n = n
        self.n_sq = n * n
        self.g = n + 1


class PrivateKey(object):
    def __init__(self, bits):
        p = generate_prime(bits / 2)
        q = generate_prime(bits / 2)
        n = p * q
        self.lam = (p - 1) * (q - 1)
        self.pub = PublicKey(bits, n)
        self.mu = inversemod(self.lam, n)


def e_add(pub, a, b):
    return (a * b) % pub.n_sq


def encrypt(plain, pub):
    while True:
        r = generate_prime(round(math.log(pub.n, 2)))
        if r > 0 and r < pub.n:
            break
    x = pow(r, pub.n, pub.n_sq)
    encrypted = (pow(pub.g, plain, pub.n_sq) * x) % pub.n_sq
    return encrypted


def decrypt(cipher, priv):
    pub = priv.pub
    x = pow(cipher, priv.lam, pub.n_sq) - 1
    decrypted = ((x // pub.n) * priv.mu) % pub.n
    return decrypted


priv = PrivateKey(128)
pub = priv.pub

x = input("Enter first value to add")
print("x =", x)
print("Encrypting x...")
ex = encrypt(int(x), pub)
print("encrypted x is =", ex)

y = input("Enter second value to add")
print("y =", y)
print("Encrypting y...")
ey = encrypt(int(y), pub)
print("encrypted x is =", ey)

print("Computing encrypted x + encrypted y...")
er = e_add(pub, ex, ey)
print("encrypted result is =", er)

print("Decrypting result...")
r0 = decrypt(er, priv)
print("result =", r0)

print("--- %s seconds ---" % (time.time() - start_time))