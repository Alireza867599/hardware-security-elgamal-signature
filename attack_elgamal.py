

import math
import random
from buggy_elgamal import modinv, sign_hash, keygen, verify_hash

def recover_k_and_x(h1, h2, r1, s1, r2, s2, p, g, y):

    n = p - 1
    delta_h = (h1 - h2) % n
    delta_s = (s1 - s2) % n

    # require invertibility
    if math.gcd(delta_s, n) != 1:
        raise ValueError(f"delta_s not invertible (gcd={math.gcd(delta_s,n)}). Try different hashes.")

    inv_delta_s = modinv(delta_s, n)
    k = (delta_h * inv_delta_s) % n

    r = r1
    if math.gcd(r, n) != 1:
        raise ValueError("r not invertible modulo n; unexpected.")

    numerator = (h1 - s1 * k) % n
    inv_r = modinv(r, n)
    x = (numerator * inv_r) % n

    return k, x

def forge_signature_same_r(h_forge, p, g, x_recovered, k_recovered, r_reused):
    n = p - 1
    inv_k = modinv(k_recovered, n)
    s_forge = ((h_forge - x_recovered * r_reused) * inv_k) % n
    return r_reused, s_forge

if __name__ == "__main__":
    p, g, y = keygen()

    # try to obtain a usable pair (h1,h2) such that delta_s invertible
    attempts = 0
    max_attempts = 200
    while attempts < max_attempts:
        # choose random hashes (attacker-controlled)
        h1 = random.randint(1, p - 2)
        h2 = random.randint(1, p - 2)
        if h1 == h2:
            continue

        r1, s1 = sign_hash(h1, p, g)
        r2, s2 = sign_hash(h2, p, g)

        # quick check that r1 == r2 (nonce reuse)
        if r1 != r2:
            # In this buggy signer r should always be same; but keep check
            attempts += 1
            continue

        delta_s = (s1 - s2) % (p - 1)
        if math.gcd(delta_s, p - 1) == 1:
            break
        attempts += 1

    if attempts >= max_attempts:
        raise SystemExit("Failed to find invertible delta_s after many attempts. Increase max_attempts or change p.")

    print("Using signatures:")
    print(" h1 =", h1, " -> (r1, s1) =", (r1, s1))
    print(" h2 =", h2, " -> (r2, s2) =", (r2, s2))

    k_rec, x_rec = recover_k_and_x(h1, h2, r1, s1, r2, s2, p, g, y)
    print("Recovered k:", k_rec)
    print("Recovered x:", x_rec)


    # Forge a signature using same r
    h_forge = random.randint(1, p - 2)
    r_f, s_f = forge_signature_same_r(h_forge, p, g, x_rec, k_rec, r1)
    print("Forged (r, s) on h_forge =", h_forge, ":", (r_f, s_f))
    ok = verify_hash(h_forge, (r_f, s_f), p, g, y)
    print("Forged signature valid?", ok)
