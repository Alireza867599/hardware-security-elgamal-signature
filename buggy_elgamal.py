# buggy_hash_signer.py
# Buggy ElGamal signer that signs hash values h.
# Secret key x and fixed nonce k are private inside this module.

from hashlib import sha256
import secrets
import math

# ---- math utils ----
def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def modinv(a, m):
    g, x, y = egcd(a % m, m)
    if g != 1:
        raise Exception("No modular inverse")
    return x % m

# ---- global secret state (simulating an HSM) ----
P = 467
G = 2

_X = None
_K = None

def _init_secrets():
    """
    Initialize secret key _X and a BUGGY reused nonce _K.
    We pick _K so that:
      - gcd(_K, n) == 1 (k invertible modulo n),
      - gcd(r, n) == 1 where r = g^k mod p (so r is invertible modulo n).
    This makes classroom demos of the attack straightforward.
    """
    global _X, _K
    n = P - 1

    # sample secret key x uniformly from [1, n-1]
    _X = secrets.randbelow(n - 1) + 1

    # choose a k such that gcd(k, n) == 1 and r = g^k mod p is invertible mod n
    while True:
        k = secrets.randbelow(n - 1) + 1
        if math.gcd(k, n) != 1:
            continue
        r = pow(G, k, P)
        if math.gcd(r, n) == 1:
            _K = k
            break

def keygen():
    global _X, _K
    if _X is None or _K is None:
        _init_secrets()
    y = pow(G, _X, P)
    return P, G, y

# ---- signing / verification API (hash-only) ----
def sign_hash(h, p, g):
    global _X, _K
    if _X is None or _K is None:
        _init_secrets()
    n = p - 1
    r = pow(g, _K, p)
    s = ((h - _X * r) * modinv(_K, n)) % n
    return r, s

def H_bytes(m, p):
    return int.from_bytes(sha256(m).digest(), "big") % (p - 1)

def verify_hash(h, sig, p, g, y):
    r, s = sig
    if not (1 <= r <= p - 1):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2
