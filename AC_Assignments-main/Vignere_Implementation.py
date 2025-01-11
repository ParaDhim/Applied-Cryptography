def vigenere_cipher(plaintext, key, mode='encrypt'):

    # Convert plaintext and key to uppercase
    plaintext = plaintext.upper()
    key = key.upper()

    # Remove non-alphabetic characters from plaintext (remove spaces)
    plaintext = ''.join(char for char in plaintext if char.isalpha())

    result = []
    key_length = len(key)

    # Iterate over each character in the plaintext
    for i, char in enumerate(plaintext):
        # Get the corresponding character from the key, cycling through if necessary
        key_char = key[i % key_length]

        # Convert the characters to their numeric values (A=0, B=1, ..., Z=25)
        char_value = ord(char) - ord('A')
        key_value = ord(key_char) - ord('A')

        if mode == 'encrypt':
            # Encrypt by shifting the plaintext character by the key character value
            # Compute new character value and ensure it wraps around with modulo 26
            new_value = (char_value + key_value) % 26
        elif mode == 'decrypt':
            # Decrypt by shifting the plaintext character back by the key character value
            # Compute new character value and ensure it wraps around with modulo 26
            new_value = (char_value - key_value + 26) % 26

        # Convert the new numeric value back to a character
        new_char = chr(new_value + ord('A'))
        # Append the resulting character to the result list
        result.append(new_char)

    return ''.join(result)


# Test the implementation
key = "PASCAL"
plaintext = input("Enter plaintext: ")
# plaintext = "she is listening"

# Encryption
ciphertext = vigenere_cipher(plaintext, key, mode='encrypt')
print(f"Plaintext: {plaintext}")
print(f"Key: {key}")
print(f"Ciphertext: {ciphertext}")

# Decryption (to verify)
decrypted_text = vigenere_cipher(ciphertext, key, mode='decrypt')
print(f"Decrypted text: {decrypted_text}")

# Verify against the given test vector (Given testcase in classroom assignment) // uncomment this to check
# expected_ciphertext = "HHWKSWXSLGNTCG"
# print(f"Expected ciphertext: {expected_ciphertext}")
# print(f"Cipher implementation is correct: {ciphertext == expected_ciphertext}")

# comment out below piece of code to check only for given test case above
# remove spaces from entered plaintext and convert it to uppercase (to match the decrypted format)
plaintext = ''.join(char for char in plaintext if char.isalpha())
plaintext = plaintext.upper()

# check this processed plaintext with the decrypted output
print(f"Cipher implementation is correct: {plaintext == decrypted_text}")
