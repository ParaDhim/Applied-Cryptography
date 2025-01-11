import random
from sympy import isprime, mod_inverse
from math import gcd


def generate_keys(p=None):
    """
    Generates public and private keys for the ElGamal Digital Signature Scheme.
    :param p: (Optional) Prime number. If not provided, a default prime is used.
    :return: (p, g, y, x) where:
             p: prime modulus,
             g: generator,
             y: public key,
             x: private key.
    """
    # Choose a large prime `p` if not provided
    if not p:
        p = 7919  # Example small prime, replace with a large prime for real use

    if not isprime(p):
        raise ValueError("p must be a prime number")

    # Choose a generator `g` (1 < g < p)
    g = random.randint(2, p - 2)

    # Choose a private key `x` (1 < x < p−1)
    x = random.randint(2, p - 2)

    # Compute public key `y = g^x mod p`
    y = pow(g, x, p)

    return p, g, y, x


def sign_message(p, g, x, m):
    """
    Generates a signature for a message m using private key x.
    :param p: prime modulus,
    :param g: generator,
    :param x: private key,
    :param m: message (0 ≤ m < p−1).
    :return: (r, s) where:
             r: first part of the signature,
             s: second part of the signature.
    """
    if not (0 <= m < p - 1):
        raise ValueError("Message m must satisfy 0 ≤ m < p−1")

    while True:
        k = random.randint(2, p - 2)  # Choose random k (1 < k < p−1)
        if gcd(k, p - 1) == 1:  # Ensure gcd(k, p-1) = 1
            break

    r = pow(g, k, p)  # r = g^k mod p
    k_inv = mod_inverse(k, p - 1)  # Compute k inverse mod (p−1)
    s = (k_inv * (m - x * r)) % (p - 1)  # s = k^(-1) * (m - xr) mod (p−1)

    return r, s


def verify_signature(p, g, y, m, r, s):
    """
    Verifies a signature (r, s) for a message m.
    :param p: prime modulus,
    :param g: generator,
    :param y: public key,
    :param m: message (0 ≤ m < p−1),
    :param r: first part of the signature,
    :param s: second part of the signature.
    :return: True if the signature is valid, False otherwise.
    """
    if not (0 < r < p):
        return False  # r must satisfy 0 < r < p

    v1 = pow(y, r, p) * pow(r, s, p) % p  # y^r * r^s mod p
    v2 = pow(g, m, p)  # g^m mod p

    return v1 == v2


p, g, y, x = generate_keys()
print(f"Public key (p, g, y): {p}, {g}, {y}")
print(f"Private key x: {x}")

# Sign a message
message = 100  # Example message
r, s = sign_message(p, g, x, message)
print(f"Signature: (r, s) = ({r}, {s})")

# Verify the signature
is_valid = verify_signature(p, g, y, message, r, s)
print(f"Is the signature valid? {is_valid}")

