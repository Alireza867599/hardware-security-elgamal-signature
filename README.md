# hardware-security-elgamal-signature
Designed a Hardware Security assignment on ElGamal digital signatures, demonstrating nonce reuse vulnerabilities, private-key recovery, and signature forgery using Python.



An educational assignment designed for a **Hardware Security** course to explore implementation vulnerabilities in the ElGamal digital signature scheme. It uses a deliberately vulnerable Python signer to demonstrate how **reusing an ephemeral nonce** can enable recovery of the signing nonce, disclosure of the private key, and creation of a valid forged signature.

The signer models selected behaviors of a Hardware Security Module (HSM) or secure element; it is **a classroom simulation, not a real HSM implementation**.

## Learning objectives

- Understand ElGamal signing and verification on message-hash values.
- Explain why each signature requires a fresh, unpredictable nonce.
- Derive the algebraic relationships exposed by nonce reuse.
- Recover the reused nonce and private signing key from two signatures under suitable invertibility conditions.
- Demonstrate signature forgery and verify the result with the public key.
- Connect cryptographic implementation errors to hardware-security risks.

## Repository contents

```text
hardware-security-elgamal-signature/
├── README.md
├── buggy_elgamal.py         # Intentionally vulnerable signer and verifier
├── attack_elgamal.py        # Nonce/private-key recovery and forgery demo
└── docs/
    └── assignment.pdf       # Assignment specification (Persian)
```

| File | Description |
| --- | --- |
| `buggy_elgamal.py` | Demonstration signer with a private key and an intentionally reused nonce, plus key generation, hash signing, and verification functions. |
| `attack_elgamal.py` | Retrieves two signatures, recovers the nonce and private key, forges a signature for another hash, and checks that verification succeeds. |
| `docs/assignment.pdf` | Original assignment brief and theoretical/practical questions. |

The instructor's worked solution/answer document is **not included** in this public-ready folder. Keep it private if this assignment is still in use.

## Requirements

- Python 3
- No third-party packages; the code uses only Python's standard library.

## Run the demonstration

Clone the repository or download it, then open a terminal in the repository directory:

```bash
python3 attack_elgamal.py
```

On Windows, `python attack_elgamal.py` may be the appropriate command.

**Important:** Keep `attack_elgamal.py` and `buggy_elgamal.py` in the same directory. The attack script imports functions from the signer using `from buggy_elgamal import ...`.

The script will print two signatures, the recovered nonce `k`, the recovered private key `x`, a forged signature, and the verification result. The random values vary between runs; a successful demo ends with:

```text
Forged signature valid? True
```

## Cryptographic background

For public parameters `p` and `g`, private key `x`, and public key `y`:

$$
y = g^x \bmod p
$$

An ElGamal signature on hash value `h` uses a nonce `k` that is invertible modulo `p - 1`:

$$
r = g^k \bmod p
$$

$$
s = k^{-1}(h - xr) \bmod (p-1)
$$

Verification checks:

$$
g^h \equiv y^r r^s \pmod p
$$

### Why nonce reuse breaks security

If two different hashes `h1` and `h2` are signed using the **same nonce** `k`, the signatures share the same `r`. Let `n = p - 1`. Subtracting the two signing equations gives:

$$
(s_1 - s_2)k \equiv h_1 - h_2 \pmod n
$$

When `s1 - s2` is invertible modulo `n`, the reused nonce can be recovered:

$$
k \equiv (h_1-h_2)(s_1-s_2)^{-1} \pmod n
$$

When `r` is also invertible modulo `n`, the private key can then be recovered:

$$
x \equiv (h_1-s_1k)r^{-1} \pmod n
$$

The provided demonstration deliberately selects parameters that make these modular-inverse steps straightforward and searches for a usable pair of signatures.

With the recovered values, the script generates a valid signature for another hash and confirms that it passes verification.

## Assignment tasks

1. **Mathematical analysis:** Derive how nonce reuse makes recovery of `k` and `x` possible.
2. **Python attack:** Implement and explain recovery of the reused nonce and private signing key.
3. **Signature forgery:** Construct a signature for a new hash and verify it against the public key.
4. **Security discussion:** Explain nonce uniqueness, signature validity, arithmetic modulo `p-1`, and the assumptions behind ElGamal security.

## Educational scope and security note

This project is intentionally insecure. The demonstration uses the small prime `p = 467` and `g = 2` to make the mathematics accessible; those parameters are **not suitable for real-world cryptographic security**. The purpose is to study implementation failures in a controlled environment, not to provide a production signing system.

**Main takeaway:** Keeping the private key inside an HSM or secure element is not sufficient if the signing implementation reuses nonces.

## Course

**Hardware Security** — Educational assignment on ElGamal digital signatures and nonce-reuse vulnerabilities.
