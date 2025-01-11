# Complete DES (Data Encryption Standard) Implementation

# Initial Permutation (IP) table for the DES algorithm.
# This table defines the rearrangement of the bits in the block.
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation (FP or IP^-1) for reversing the Initial Permutation after the rounds.
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion table (E) that expands 32-bit input to 48 bits for XOR with the subkey.
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S-boxes used in the DES algorithm for the substitution step in each round.
# There are 8 S-boxes, each containing a 4x16 matrix.
S_BOXES = [
    # S1 box
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2 box
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3 box
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4 box
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5 box
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6 box
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7 box
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8 box
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# P-box permutation used to reorder bits after S-box substitution.
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Permuted Choice 1 (PC-1) used for initial key permutation before generating subkeys.
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2 (PC-2) used for selecting the 48 bits from 56-bit key after shifting.
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Shift schedule defining how many left shifts to perform on the key in each round.
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


# Function to permute a block of bits using a given permutation table.
def permute(block, table):
    return ''.join(block[i - 1] for i in table)


# Convert a string of characters to its binary (bit) representation.
def string_to_bit_array(text):
    return ''.join(format(ord(char), '08b') for char in text)


# Convert a hexadecimal string to its binary (bit) representation.
def hex_to_bit_array(hex_string):
    return ''.join(format(int(char, 16), '04b') for char in hex_string)


# Convert a binary (bit) string to its hexadecimal representation.
def bit_array_to_hex(bit_array):
    return '{:0{}X}'.format(int(bit_array, 2), len(bit_array) // 4)


# Left-shift a bit string by 'n' positions.
def left_shift(bits, n):
    return bits[n:] + bits[:n]


# Generate 16 subkeys from the provided key using PC-1, shifts, and PC-2.
def generate_subkeys(key):
    # Convert the key from hex to binary.
    key_bits = hex_to_bit_array(key)
    # Permute the key using PC-1 to get the 56-bit key.
    key_56 = permute(key_bits, PC1)
    # Split the key into two halves (28 bits each).
    left, right = key_56[:28], key_56[28:]
    subkeys = []
    # Generate 16 subkeys.
    for shift in SHIFT_SCHEDULE:
        # Left-shift both halves based on the shift schedule.
        left = left_shift(left, shift)
        right = left_shift(right, shift)
        # Combine the halves and permute using PC-2 to get the subkey.
        subkey = permute(left + right, PC2)
        subkeys.append(subkey)
    return subkeys


# Perform one round of the DES algorithm, which includes expansion, XOR, S-box substitution, and P-box permutation.
def des_round(left, right, subkey):
    # Expand the 32-bit right half to 48 bits using the expansion table.
    expanded = permute(right, E)

    # XOR the expanded right half with the subkey.
    xored = ''.join(str(int(a) ^ int(b)) for a, b in zip(expanded, subkey))

    # S-box substitution: Break the 48-bit XOR result into 8 chunks of 6 bits.
    sbox_output = ''
    for i in range(8):
        chunk = xored[i * 6:(i + 1) * 6]
        row = int(chunk[0] + chunk[5], 2)  # First and last bit form the row.
        col = int(chunk[1:5], 2)           # Middle four bits form the column.
        # Substitute the 6-bit chunk with a 4-bit result from the S-box.
        sbox_output += format(S_BOXES[i][row][col], '04b')

    # Permute the S-box output using the P-box permutation.
    permuted = permute(sbox_output, P)

    # XOR the permuted result with the left half to get the new right half.
    result = ''.join(str(int(a) ^ int(b)) for a, b in zip(left, permuted))

    return result


# Count the number of differing bits between two bit strings.
def count_bit_differences(a, b):
    return sum(bit_a != bit_b for bit_a, bit_b in zip(a, b))


# Perform DES encryption on a 64-bit plaintext using the provided key.
def des_encrypt(plaintext, key):
    # Apply the initial permutation to the plaintext.
    block = permute(hex_to_bit_array(plaintext), IP)

    # Split the permuted block into left and right halves.
    left, right = block[:32], block[32:]

    # Generate 16 subkeys for the 16 rounds.
    subkeys = generate_subkeys(key)

    print(f"After initial permutation: {bit_array_to_hex(block)}")
    print(f"After splitting: L0={bit_array_to_hex(left)} R0={bit_array_to_hex(right)}\n")

    # Perform 16 rounds of DES.
    for i in range(16):
        new_right = des_round(left, right, subkeys[i])
        # After each round, the new right half becomes the left half, and the new left half becomes the right.
        left, right = right, new_right
        print(f"Round {i + 1:<2} Left: {bit_array_to_hex(left):<8} Right: {bit_array_to_hex(right):<8} Round Key: {bit_array_to_hex(subkeys[i])}")

    # Combine the final right and left halves (note the swap) and apply the final permutation.
    combined = right + left
    ciphertext = permute(combined, FP)

    return bit_array_to_hex(ciphertext)


# Same as des_encrypt but also returns intermediate states for avalanche analysis.
def des_encrypt_with_states(plaintext, key):
    # Apply the initial permutation to the plaintext.
    block = permute(hex_to_bit_array(plaintext), IP)

    # Split into left and right halves.
    left, right = block[:32], block[32:]

    # Generate subkeys.
    subkeys = generate_subkeys(key)

    # List to store the intermediate states (left and right halves).
    states = [(left, right)]

    # Perform 16 rounds.
    for i in range(16):
        new_right = des_round(left, right, subkeys[i])
        left, right = right, new_right
        states.append((left, right))

    # Combine the final right and left halves and apply the final permutation.
    combined = right + left
    ciphertext = permute(combined, FP)

    return bit_array_to_hex(ciphertext), states


# Analyze the avalanche effect by comparing how small changes in the plaintext affect the ciphertext.
def analyze_avalanche_effect(plaintext1, plaintext2, key):
    # Encrypt both plaintexts and retrieve their intermediate states.
    ciphertext1, states1 = des_encrypt_with_states(plaintext1, key)
    ciphertext2, states2 = des_encrypt_with_states(plaintext2, key)

    print(f"Plaintext 1: {plaintext1}")
    print(f"Plaintext 2: {plaintext2}")
    print(f"Key: {key}")
    print(f"Ciphertext 1: {ciphertext1}")
    print(f"Ciphertext 2: {ciphertext2}")
    print()

    # Display left and right halves for both plaintexts at each round.
    for i in range(17):
        print(f'Left of Test1:{states1[i][0]} Right of Test1:{states1[i][1]}')
        print(f'Left Of Test2:{states2[i][0]} Right Of Test2:{states2[i][1]}')
        print("============================================================================================================")

    # Display the bit differences between the two states after each round.
    print("\nBit differences after each round:")
    print("Round\tLeft\tRight\tTotal")
    print("-----\t----\t-----\t-----")

    bit_differences = []

    for i in range(17):  # 16 rounds + initial state
        left_diff = count_bit_differences(states1[i][0], states2[i][0])
        right_diff = count_bit_differences(states1[i][1], states2[i][1])
        total_diff = left_diff + right_diff
        bit_differences.append(total_diff)
        print(f"{i:2d}\t{left_diff:2d}\t{right_diff:2d}\t{total_diff:2d}")

    # Summary of bit differences after each round.
    print("\nRounds:                 " + "   ".join(f"{i:2d}" for i in range(1, 17)))
    print("Bit differences:        " + "   ".join(f"{diff:2d}" for diff in bit_differences[1:]))


# Main function to run the DES encryption and the avalanche effect test.
if __name__ == "__main__":
    # Test case: Encrypt a 64-bit plaintext using a 64-bit key.
    plaintext = "123456ABCD132536"
    key = "AABB09182736CCDD"

    print(f"Plaintext: {plaintext}")
    print(f"Key: {key}")
    print()

    # Perform DES encryption.
    ciphertext = des_encrypt(plaintext, key)
    print(f"\nCiphertext: {ciphertext}")

    # Analyze avalanche effect with two slightly different plaintexts.
    print("\nTest Case: Avalanche Effect")
    plaintext1 = "0000000000000000"
    plaintext2 = "0000000000000001"
    key = "22234512987ABB23"
    analyze_avalanche_effect(plaintext1, plaintext2, key)
