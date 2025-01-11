plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
key = [0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98]
expected_ciphertext = [0xff, 0x0b, 0x84, 0x4a, 0x08, 0x53, 0xbf, 0x7c, 0x69, 0x34, 0xab, 0x43, 0x64, 0x14, 0x8f, 0xb9]

print("prev plain", plaintext)
# Convert plaintext to a 4x4 matrix for rearrangement
plaintext_matrix = [[plaintext[i + 4 * j] for i in range(4)] for j in range(4)]

# Rearrange plaintext_matrix into a column-major list
plaintext = [plaintext_matrix[j][i] for i in range(4) for j in range(4)]

# Display the updated plaintext
print("Updated plaintext:", plaintext)

# Optionally update the expected ciphertext similarly
expected_ciphertext_matrix = [[expected_ciphertext[i + 4 * j] for i in range(4)] for j in range(4)]
expected_ciphertext = [expected_ciphertext_matrix[j][i] for i in range(4) for j in range(4)]

# Display the updated expected ciphertext
print("Updated expected_ciphertext:", expected_ciphertext)
