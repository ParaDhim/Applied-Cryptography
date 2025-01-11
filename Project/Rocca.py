import os
from AES import substitute, shiftRows, mixColumns, addRoundKey, make2D
import time

# Little Endians
# Truncate

z0 = "428a2f98d728ae227137449123ef65cd"
z1 = "b5c0fbcfec4d3b2fe9b5dba58189dbbc"

# def AES(X, Y):
#     X = make2D(list(X))
#     Y = make2D(list(Y))
#     out = addRoundKey(mixColumns(shiftRows(substitute(X))), Y)
#     out = [item for sublist in zip(*out) for item in sublist]
#     return bytes([int(str(hex_str), 16) for hex_str in out])


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


def _rotl32(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def sub_bytes(state):
    sb = [0] * 16
    for i in range(4):
        for j in range(4):
            # Extract each byte and apply S-box substitution
            byte_val = (state[i] >> (j * 8)) & 0xFF
            sb[i * 4 + j] = SBox[byte_val]
    return sb


def shift_rows(sb):
    result = [0] * 4
    for j in range(4):
        result[j] = (sb[(j * 4 + 0) % 16] << 24) | \
                    (sb[(j * 4 + 5) % 16] << 0) | \
                    (sb[(j * 4 + 10) % 16] << 8) | \
                    (sb[(j * 4 + 15) % 16] << 16)
    return result


def mix_columns(shifted_state):
    result = [0] * 4
    for j in range(4):
        w = shifted_state[j]
        # Optimized implementation using rotations and XOR operations
        t = _rotl32(w, 16) ^ \
            ((w << 1) & 0xfefefefe) ^ \
            (((w >> 7) & 0x01010101) * 0x1b)
        result[j] = w ^ t ^ _rotl32(t, 8)
    return result


def add_round_key(state, round_key):
    return [state[i] ^ round_key[i] for i in range(4)]


def aes_enc_round(state, round_key):
    state = [int.from_bytes(state[i:i + 4], byteorder='big') for i in range(0, len(state), 4)]
    round_key = [int.from_bytes(round_key[i:i + 4], byteorder='big') for i in range(0, len(round_key), 4)]
    result = add_round_key(mix_columns(shift_rows(sub_bytes(state))), round_key)
    byte_state = [v.to_bytes(4, byteorder='big') for v in result]
    return b''.join(byte_state)


def convertAndPad(message, m):
    if m == 0:
        byte_rep = bytes([ord(char) for char in message])
    else:
        byte_rep = message
    current_length = len(byte_rep)
    required_length = ((current_length + 31) // 32) * 32
    padding_needed = required_length - current_length
    if padding_needed > 0:
        byte_rep += b'\x00' * padding_needed
    return byte_rep


def generate():
    key_bytes = os.urandom(32)
    nonce_bytes = os.urandom(16)
    return key_bytes[:16], key_bytes[16:], nonce_bytes


def roundUpdate(S, X0, X1):
    S_new = [None] * 8
    S_new[0] = bytes(a ^ b for a, b in zip(S[7], X0))
    S_new[1] = aes_enc_round(S[0], S[7])
    S_new[2] = bytes(a ^ b for a, b in zip(S[1], S[6]))
    S_new[3] = aes_enc_round(S[2], S[1])
    S_new[4] = bytes(a ^ b for a, b in zip(S[3], X1))
    S_new[5] = aes_enc_round(S[4], S[3])
    S_new[6] = aes_enc_round(S[5], S[4])
    S_new[7] = bytes(a ^ b for a, b in zip(S[0], S[6]))
    return S_new


def initialize_state(N, K0, K1):
    S = [None] * 8
    S[0] = K1
    S[1] = N
    S[2] = bytes.fromhex(z0)[::-1]
    S[3] = bytes.fromhex(z1)[::-1]
    S[4] = bytes([k ^ n for k, n in zip(K1, N)])
    S[5] = bytes([0x00] * 16)
    S[6] = K0
    S[7] = bytes([0x00] * 16)
    for i in range(20):
        S = roundUpdate(S, bytes.fromhex(z0)[::-1], bytes.fromhex(z1)[::-1])
    S[0] = bytes([k ^ n for k, n in zip(S[0], K0)])
    S[4] = bytes([k ^ n for k, n in zip(S[4], K1)])
    return S


def processAD(S, AD, m):
    AD = convertAndPad(AD, m)
    d = len(AD) // 32
    for i in range(d):
        S = roundUpdate(S, AD[32 * i:32 * i + 16], AD[32 * i + 16:32 * i + 32])
    return S


def finalisation(S, AD, M):
    AD = AD.to_bytes(16, byteorder='little')
    M = M.to_bytes(16, byteorder='little')
    for _ in range(20):
        S = roundUpdate(S, AD, M)
    T = [0] * len(S[0])
    for row in S:
        for i in range(len(row)):
            T[i] ^= row[i]
    return bytes(T)


def encrypt(S, M_padded):
    m = len(M_padded) // 32
    C = b""
    for i in range(m):
        M0 = M_padded[32 * i: 32 * i + 16]
        M1 = M_padded[32 * i + 16: 32 * (i + 1)]
        C0 = bytes([s ^ m for s, m in zip(aes_enc_round(S[1], S[5]), M0)])
        C1 = bytes([s ^ m for s, m in zip(aes_enc_round(bytes([s ^ x for s, x in zip(S[0], S[4])]), S[2]), M1)])
        C += C0 + C1
        S = roundUpdate(S, M0, M1)
    return C, S


def decrypt(S, C_padded):
    c = len(C_padded) // 32
    M = b""
    for i in range(c):
        C0 = C_padded[32 * i: 32 * i + 16]
        C1 = C_padded[32 * i + 16: 32 * (i + 1)]
        M0 = bytes([s ^ m for s, m in zip(aes_enc_round(S[1], S[5]), C0)])
        M1 = bytes([s ^ m for s, m in zip(aes_enc_round(bytes([s ^ x for s, x in zip(S[0], S[4])]), S[2]), C1)])
        M += M0 + M1
        S = roundUpdate(S, M0, M1)
    return M, S


def rocca_encrypt(K0, K1, N, AD, M):
    C = None
    S = initialize_state(N, K0, K1)
    if AD:
        S = processAD(S, AD, 1)
    if M:
        M_padded = convertAndPad(M, 1)
        C, S = encrypt(S, M_padded)
    # C = C[:len(M)]
    return C  # , finalisation(S, len(AD), len(M_padded))


def rocca_decrypt(K0, K1, N, AD, C, T):
    M = None
    S = initialize_state(N, K0, K1)
    if AD:
        S = processAD(S, AD, 1)
    if C:
        C = convertAndPad(C, 1)
        M, S = decrypt(S, C)
    return M if T == finalisation(S, len(AD), len(C)) else None


# Example Usage
if __name__ == "__main__":
    K0, K1, N = generate()
    M_og = os.urandom(32)
    AD = os.urandom(0)
    start = time.perf_counter()
    C = rocca_encrypt(K0, K1, N, AD, M_og)
    end = time.perf_counter()
    print(f"Time Elapsed: {(end - start) * 1000}ms")
    M_og = os.urandom(128)
    AD = os.urandom(0)
    start = time.perf_counter()
    C = rocca_encrypt(K0, K1, N, AD, M_og)
    end = time.perf_counter()
    print(f"Time Elapsed: {(end - start) * 1000}ms")
    M_og = os.urandom(1024)
    AD = os.urandom(0)
    start = time.perf_counter()
    C = rocca_encrypt(K0, K1, N, AD, M_og)
    end = time.perf_counter()
    print(f"Time Elapsed: {(end - start) * 1000}ms")
    # print(f"C(len={len(C)}): {C}")
    # M = rocca_decrypt(K0, K1, N, AD, C, None)
    # print("Success") if M == M_og else print("Fail")
