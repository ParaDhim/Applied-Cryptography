# class Trivium:
#     def __init__(self, key, iv):
#         self.state = [0] * 288

#         # Load key into state
#         key_bits = self.hex_to_bits(key)
#         for i in range(80):
#             self.state[i] = int(key_bits[i])

#         # Load IV into state
#         iv_bits = self.hex_to_bits(iv)
#         for i in range(80):
#             self.state[i + 93] = int(iv_bits[i])

#         # Set last 3 bits to 1
#         self.state[285] = self.state[286] = self.state[287] = 1

#         # Key and IV setup
#         for _ in range(4 * 288):
#             self.update_state()

#     def hex_to_bits(self, hex_string):
#         return ''.join(bin(int(hex_string[i:i+2], 16))[2:].zfill(8) for i in range(0, len(hex_string), 2))

#     def update_state(self):
#         t1 = self.state[65] ^ (self.state[90] & self.state[91]) ^ self.state[92] ^ self.state[170]
#         t2 = self.state[161] ^ (self.state[174] & self.state[175]) ^ self.state[176] ^ self.state[263]
#         t3 = self.state[242] ^ (self.state[285] & self.state[286]) ^ self.state[287] ^ self.state[68]
        
#         self.state = [t3] + self.state[:92] + [t1] + self.state[93:176] + [t2] + self.state[177:287]

#     def generate_keystream(self, num_bits):
#         keystream = []
#         for _ in range(num_bits):
#             t1 = self.state[65] ^ self.state[92]
#             t2 = self.state[161] ^ self.state[176]
#             t3 = self.state[242] ^ self.state[287]

#             z = t1 ^ t2 ^ t3
#             keystream.append(z)

#             t1 = t1 ^ (self.state[90] & self.state[91]) ^ self.state[170]
#             t2 = t2 ^ (self.state[174] & self.state[175]) ^ self.state[263]
#             t3 = t3 ^ (self.state[285] & self.state[286]) ^ self.state[68]

#             self.state = [t3] + self.state[:287]
#             self.state[93] = t1
#             self.state[177] = t2
        
#         return keystream

# def binary_to_hex(binary_string):
#     return ''.join(hex(int(binary_string[i:i+4], 2))[2:].upper() for i in range(0, len(binary_string), 4))

# def generate_keystream(key, iv, num_bits=512):
#     trivium = Trivium(key, iv)
#     keystream_bits = trivium.generate_keystream(num_bits)
#     keystream_binary = ''.join(map(str, keystream_bits))
#     return binary_to_hex(keystream_binary)

# # Test vectors
# test_vectors = [
#     ("00000000000000000000", "00000000000000000000"),
#     ("80000000000000000000", "00000000000000000000")
# ]

# for key, iv in test_vectors:
#     print(f"• Key = 0x{key}")
#     print(f"  IV = 0x{iv}")
#     keystream = generate_keystream(key, iv)
#     print(f"  keystream = 0x{' '.join([keystream[i:i+4] for i in range(0, len(keystream), 4)])}")
#     print()


# Function to reverse bits in a byte
def reverse_bits_in_byte(byte):
    return '{:08b}'.format(int(byte, 16))[::-1]

# Function to convert hex string to reversed bits
def hex_to_bits_reversed(hex_string):
    return ''.join(reverse_bits_in_byte(hex_string[i:i+2]) for i in range(0, len(hex_string), 2))

# Trivium Cipher Class
class Trivium:
    def __init__(self, key, iv):
        self.state = [0] * 288

        # Load key into state with reversed bits
        key_bits = hex_to_bits_reversed(key)
        for i in range(80):
            self.state[i] = int(key_bits[i])

        # Load IV into state with reversed bits
        iv_bits = hex_to_bits_reversed(iv)
        for i in range(80):
            self.state[i + 93] = int(iv_bits[i])

        # Set the last 3 bits to 1
        self.state[285] = self.state[286] = self.state[287] = 1

        # Key and IV setup (Warm-up phase)
        for _ in range(4 * 288):
            self.update_state()

    def update_state(self):
        t1 = self.state[65] ^ (self.state[90] & self.state[91]) ^ self.state[92] ^ self.state[170]
        t2 = self.state[161] ^ (self.state[174] & self.state[175]) ^ self.state[176] ^ self.state[263]
        t3 = self.state[242] ^ (self.state[285] & self.state[286]) ^ self.state[287] ^ self.state[68]
        
        # Update the state with new values
        self.state = [t3] + self.state[:92] + [t1] + self.state[93:176] + [t2] + self.state[177:287]

    def generate_keystream(self, num_bits):
        keystream = []
        for _ in range(num_bits):
            t1 = self.state[65] ^ self.state[92]
            t2 = self.state[161] ^ self.state[176]
            t3 = self.state[242] ^ self.state[287]

            z = t1 ^ t2 ^ t3
            keystream.append(z)

            # Update the state based on the Trivium algorithm
            t1 = t1 ^ (self.state[90] & self.state[91]) ^ self.state[170]
            t2 = t2 ^ (self.state[174] & self.state[175]) ^ self.state[263]
            t3 = t3 ^ (self.state[285] & self.state[286]) ^ self.state[68]

            self.state = [t3] + self.state[:287]
            self.state[93] = t1
            self.state[177] = t2
        
        return keystream

# Function to convert binary string to hexadecimal
def binary_to_hex(binary_string):
    # Ensure that binary string length is a multiple of 4 by padding
    if len(binary_string) % 4 != 0:
        binary_string = binary_string.zfill(len(binary_string) + (4 - len(binary_string) % 4))
    return ''.join(hex(int(binary_string[i:i+4], 2))[2:].upper() for i in range(0, len(binary_string), 4))

# Function to generate a keystream using Trivium cipher
def generate_keystream(key, iv, num_bits=512):
    trivium = Trivium(key, iv)
    keystream_bits = trivium.generate_keystream(num_bits)
    keystream_binary = ''.join(map(str, keystream_bits))
    return binary_to_hex(keystream_binary)

# Test vectors
test_vectors = [
    ("00000000000000000000", "00000000000000000000"),
    ("80000000000000000000", "00000000000000000000")
]

# Running the tests
for key, iv in test_vectors:
    print(f"• Key = 0x{key}")
    print(f"  IV = 0x{iv}")
    keystream = generate_keystream(key, iv)
    # Formatting the output for better readability
    print(f"  Keystream = 0x{' '.join([keystream[i:i+4] for i in range(0, len(keystream), 4)])}")
    print()
