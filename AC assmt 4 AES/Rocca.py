import os
import time

# Precomputed constants
Z0 = bytes.fromhex("428a2f98d728ae227137449123ef65cd")[::-1]
Z1 = bytes.fromhex("b5c0fbcfec4d3b2fe9b5dba58189dbbc")[::-1]


def _rotl32(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def sub_bytes(state, sbox):
    """Applies S-Box substitution to the state."""
    return [sbox[(word >> (i * 8)) & 0xFF] for word in state for i in range(4)]


def shift_rows(sb):
    """Performs the ShiftRows operation."""
    return [
        (sb[(j * 4 + 0) % 16] << 24)
        | (sb[(j * 4 + 5) % 16] << 0)
        | (sb[(j * 4 + 10) % 16] << 8)
        | (sb[(j * 4 + 15) % 16] << 16)
        for j in range(4)
    ]


def mix_columns(state):
    """Performs the MixColumns operation."""
    return [
        state[j] ^ t ^ _rotl32(t, 8)
        for j, w in enumerate(state)
        for t in [
            _rotl32(w, 16)
            ^ ((w << 1) & 0xFEFEFEFE)
            ^ (((w >> 7) & 0x01010101) * 0x1b)
        ]
    ]


def add_round_key(state, round_key):
    """XORs the state with the round key."""
    return [state[i] ^ round_key[i] for i in range(len(state))]


def aes_enc_round(state, round_key, sbox):
    """Performs a single AES round."""
    state = [int.from_bytes(state[i:i + 4], "big") for i in range(0, len(state), 4)]
    round_key = [
        int.from_bytes(round_key[i:i + 4], "big") for i in range(0, len(round_key), 4)
    ]
    result = add_round_key(mix_columns(shift_rows(sub_bytes(state, sbox))), round_key)
    return b"".join(word.to_bytes(4, "big") for word in result)


def convert_and_pad(data, is_string=False):
    """Converts and pads data to a multiple of 32 bytes."""
    if is_string:
        data = bytes(ord(c) for c in data)
    padding = (32 - len(data) % 32) % 32
    return data + b"\x00" * padding


def generate_keys():
    """Generates random keys and nonce."""
    key = os.urandom(32)
    return key[:16], key[16:], os.urandom(16)


def round_update(S, X0, X1, sbox):
    """Updates the state for a single round."""
    return [
        bytes(a ^ b for a, b in zip(S[7], X0)),
        aes_enc_round(S[0], S[7], sbox),
        bytes(a ^ b for a, b in zip(S[1], S[6])),
        aes_enc_round(S[2], S[1], sbox),
        bytes(a ^ b for a, b in zip(S[3], X1)),
        aes_enc_round(S[4], S[3], sbox),
        aes_enc_round(S[5], S[4], sbox),
        bytes(a ^ b for a, b in zip(S[0], S[6])),
    ]


def initialize_state(nonce, k0, k1, sbox):
    """Initializes the state matrix."""
    S = [
        k1,
        nonce,
        Z0,
        Z1,
        bytes(a ^ b for a, b in zip(k1, nonce)),
        bytes(16),
        k0,
        bytes(16),
    ]
    for _ in range(20):
        S = round_update(S, Z0, Z1, sbox)
    S[0] = bytes(a ^ b for a, b in zip(S[0], k0))
    S[4] = bytes(a ^ b for a, b in zip(S[4], k1))
    return S


def process_associated_data(S, AD, sbox):
    """Processes associated data."""
    AD = convert_and_pad(AD)
    for i in range(0, len(AD), 32):
        S = round_update(S, AD[i : i + 16], AD[i + 16 : i + 32], sbox)
    return S


def encrypt(S, M, sbox):
    """Encrypts the message."""
    M_padded = convert_and_pad(M)
    C = b""
    for i in range(0, len(M_padded), 32):
        M0, M1 = M_padded[i : i + 16], M_padded[i + 16 : i + 32]
        C0 = bytes(
            a ^ b
            for a, b in zip(aes_enc_round(S[1], S[5], sbox), M0)
        )
        C1 = bytes(
            a ^ b
            for a, b in zip(aes_enc_round(bytes([s ^ x for s, x in zip(S[0], S[4])]), S[2], sbox), M1)
        )
        C += C0 + C1
        S = round_update(S, M0, M1, sbox)
    return C, S


def rocca_encrypt(k0, k1, nonce, ad, m, sbox):
    """Main Rocca encryption function."""
    S = initialize_state(nonce, k0, k1, sbox)
    if ad:
        S = process_associated_data(S, ad, sbox)
    if m:
        return encrypt(S, m, sbox)
    return None


# Example Usage
if __name__ == "__main__":
    SBox = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ]
    k0, k1, nonce = generate_keys()
    plaintext = os.urandom(32)
    associated_data = os.urandom(0)

    start = time.perf_counter()
    ciphertext, _ = rocca_encrypt(k0, k1, nonce, associated_data, plaintext, SBox)
    end = time.perf_counter()
    print(f" Plaintext Size: 256 bits - Time: {(end - start) * 1000:.2f} milliseconds")


    plaintext = os.urandom(128)
    associated_data = os.urandom(0)

    start = time.perf_counter()
    ciphertext, _ = rocca_encrypt(k0, k1, nonce, associated_data, plaintext, SBox)
    end = time.perf_counter()
    print(f"Plaintext Size: 1024 bits - Time: {(end - start) * 1000:.2f} milliseconds")


    plaintext = os.urandom(1024)
    associated_data = os.urandom(0)

    start = time.perf_counter()
    ciphertext, _ = rocca_encrypt(k0, k1, nonce, associated_data, plaintext, SBox)
    end = time.perf_counter()

    # print(f"Ciphertext (Hex): {ciphertext.hex()}")
    print(f"Plaintext Size: 8192 bits - Time: {(end - start) * 1000:.2f} milliseconds")