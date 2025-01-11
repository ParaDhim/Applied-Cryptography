# AES-128 Implementation

# S-box
Sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Round constant
Rcon = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
]

def sub_bytes(state):
    return [[Sbox[byte] for byte in word] for word in state]

def shift_rows(state):
    # print("inside shift")
    print(state)
    return [state[i][i:] + state[i][:i] for i in range(4)]

def mix_columns(state):
    def mix_column(column):
        temp = column.copy()
        column[0] = gmul(temp[0], 2) ^ gmul(temp[3], 1) ^ gmul(temp[2], 1) ^ gmul(temp[1], 3)
        column[1] = gmul(temp[1], 2) ^ gmul(temp[0], 1) ^ gmul(temp[3], 1) ^ gmul(temp[2], 3)
        column[2] = gmul(temp[2], 2) ^ gmul(temp[1], 1) ^ gmul(temp[0], 1) ^ gmul(temp[3], 3)
        column[3] = gmul(temp[3], 2) ^ gmul(temp[2], 1) ^ gmul(temp[1], 1) ^ gmul(temp[0], 3)
        return column

    return [mix_column([state[row][col] for row in range(4)]) for col in range(4)]

def add_round_key(state, round_key):
    return [[state[i][j] ^ round_key[i][j] for j in range(4)] for i in range(4)]

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p

def key_expansion(key, rounds):
    w = [key[i:i+4] for i in range(0, len(key), 4)]
    for i in range(4, 4 * (rounds + 1)):
        temp = w[i-1]
        if i % 4 == 0:
            temp = [Sbox[b] for b in (temp[1:] + temp[:1])]
            temp[0] ^= Rcon[i//4 - 1]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    return [w[i:i+4] for i in range(0, len(w), 4)]

def encrypt(plaintext, key, rounds):
    state = [[plaintext[i+4*j] for i in range(4)] for j in range(4)]
    round_keys = key_expansion(key, rounds)

    print_state(state, "Initial state")
    print_state(round_keys[0], "Round key")
    state = add_round_key(state, round_keys[0])
    print_state(state, "After AddRoundKey")
    
    for round in range(1, rounds + 1):
        print(f"\nRound {round}")
        
        state = sub_bytes(state)
        print_state(state, "After SubBytes")
        
        state = shift_rows(state)
        print_state(state, "After ShiftRows")
        
        if round < rounds:
            state = mix_columns(state)
            print_state(state, "After MixColumns")
        
        print_state(round_keys[round], "Round key")
        state = add_round_key(state, round_keys[round])
        print_state(state, "After AddRoundKey")

    return [state[j][i] for i in range(4) for j in range(4)]

# def print_state(state, label):
#     print(f"{label}:")
#     for i in range(4):
#         print(" ".join(f"{state[j][i]:02x}" for j in range(4)))
#     print()

def print_state(state, label):
    print(f"{label}:")
    for row in state:
        print(" ".join(f"{byte:02x}" for byte in row))
    print()

def main():
    # Test vectors
    plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
    key = [0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98]
    expected_ciphertext = [0xff, 0x0b, 0x84, 0x4a, 0x08, 0x53, 0xbf, 0x7c, 0x69, 0x34, 0xab, 0x43, 0x64, 0x14, 0x8f, 0xb9]

    rounds = int(input("Enter the number of rounds (1-10): "))
    if rounds < 1 or rounds > 10:
        print("Invalid number of rounds. Please enter a number between 1 and 10.")
        return

    print(f"\nAES-128 Encryption (Rounds: {rounds})")
    print_state([[plaintext[i+4*j] for i in range(4)] for j in range(4)], "Plaintext")
    print("print",[[plaintext[i+4*j] for i in range(4)] for j in range(4)])
    print_state([[key[i+4*j] for i in range(4)] for j in range(4)], "Key")

    print("\nEncryption Process:")
    ciphertext = encrypt(plaintext, key, rounds)
    
    print("\nFinal Result:")
    print_state([[ciphertext[i+4*j] for i in range(4)] for j in range(4)], "Ciphertext")

    if ciphertext == expected_ciphertext:
        print("Encryption successful! The ciphertext matches the expected output.")
    else:
        print("Encryption result does not match the expected ciphertext.")
        print("Expected:")
        print_state([[expected_ciphertext[i+4*j] for i in range(4)] for j in range(4)], "Expected Ciphertext")

# def main():
#     # Take plaintext input as a hexadecimal matrix from the user
#     print("Enter the plaintext (16 hexadecimal values separated by space):")
#     plaintext = list(map(lambda x: int(x, 16), input().strip().split()))

#     # Take key input as a hexadecimal matrix from the user
#     print("Enter the key (16 hexadecimal values separated by space):")
#     key = list(map(lambda x: int(x, 16), input().strip().split()))

#     # Number of rounds
#     rounds = 10  # Fixed for AES-128, you can ask the user for flexibility

#     print(f"\nAES-128 Encryption (Rounds: {rounds})")
#     print_state([[plaintext[i + 4 * j] for i in range(4)] for j in range(4)], "Plaintext")
#     print_state([[key[i + 4 * j] for i in range(4)] for j in range(4)], "Key")

#     print("\nEncryption Process:")
#     ciphertext = encrypt(plaintext, key, rounds)
    
#     print("\nFinal Result:")
#     print_state([[ciphertext[i + 4 * j] for i in range(4)] for j in range(4)], "Ciphertext")

if __name__ == "__main__":
    main()