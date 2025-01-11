def vigenere_cipher(plaintext, key, mode='encrypt'):
    """
    Implements the Vigenere Cipher for encryption and decryption.
    
    Args:
    plaintext (str): The text to be encrypted or decrypted.
    key (str): The encryption/decryption key.
    mode (str): 'encrypt' for encryption, 'decrypt' for decryption.
    
    Returns:
    str: The encrypted or decrypted text.
    """
    
    # Convert plaintext and key to uppercase
    plaintext = plaintext.upper()
    key = key.upper()
    
    # Remove non-alphabetic characters from plaintext
    plaintext = ''.join(char for char in plaintext if char.isalpha())
    
    result = []
    key_length = len(key)
    
    for i, char in enumerate(plaintext):
        # Get the corresponding key character
        key_char = key[i % key_length]
        
        # Convert characters to their ASCII values (A=0, B=1, ..., Z=25)
        char_value = ord(char) - ord('A')
        key_value = ord(key_char) - ord('A')
        
        if mode == 'encrypt':
            # For encryption: (plaintext + key) mod 26
            new_value = (char_value + key_value) % 26
        else:  # mode == 'decrypt'
            # For decryption: (plaintext - key + 26) mod 26
            new_value = (char_value - key_value + 26) % 26
        
        # Convert the new value back to a character
        new_char = chr(new_value + ord('A'))
        result.append(new_char)
    
    return ''.join(result)

# def vigenere_cipher(plaintext, key, mode='encrypt'):
#     """
#     Implements the Vigenere Cipher for encryption and decryption.
    
#     Args:
#     plaintext (str): The text to be encrypted or decrypted.
#     key (str): The encryption/decryption key.
#     mode (str): 'encrypt' for encryption, 'decrypt' for decryption.
    
#     Returns:
#     str: The encrypted or decrypted text.
#     """
    
#     # Convert plaintext and key to uppercase
#     # plaintext = plaintext
#     # key = key
    
#     # Remove non-alphabetic characters from plaintext
#     # plaintext = ''.join(char for char in plaintext if char.isalpha())
    
#     result = []
#     key_length = len(key)
    
#     for i, char in enumerate(plaintext):
#         # Get the corresponding key character
#         key_char = key[i % key_length]
        
#         # Convert characters to their ASCII values (A=0, B=1, ..., Z=25)
#         char_value = ord(char) - ord('A')
#         key_value = ord(key_char) - ord('A')
        
#         if mode == 'encrypt':
#             # For encryption: (plaintext + key) mod 26
#             new_value = (char_value + key_value) % 26
#         else:  # mode == 'decrypt'
#             # For decryption: (plaintext - key + 26) mod 26
#             new_value = (char_value - key_value + 26) % 26
        
#         # Convert the new value back to a character
#         new_char = chr(new_value + ord('A'))
#         result.append(new_char)
    
#     return ''.join(result)

# Test the implementation
key = "PASCAL"
plaintext = "she is listening"

# Encryption
ciphertext = vigenere_cipher(plaintext, key, mode='encrypt')
print(f"Plaintext: {plaintext}")
print(f"Key: {key}")
print(f"Ciphertext: {ciphertext}")

# Decryption (to verify)
decrypted_text = vigenere_cipher(ciphertext, key, mode='decrypt')
print(f"Decrypted text: {decrypted_text}")

# Verify against the given test vector
expected_ciphertext = "HHWKSWXSLGNTCG"
print(f"Expected ciphertext: {expected_ciphertext}")
print(f"Cipher implementation is correct: {ciphertext == expected_ciphertext}")