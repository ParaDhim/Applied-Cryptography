# # import numpy as np

# # def reverse_bits_in_byte(byte):
# #     return '{:08b}'.format(int(byte, 16))[::-1]

# # def hex_to_bits(hex_string):
# #     return ''.join([reverse_bits_in_byte(hex_string[i:i+2]) for i in range(0, len(hex_string), 2)])

# # def bits_to_hex(bits):
# #     return ''.join([hex(int(bits[i:i+4], 2))[2:] for i in range(0, len(bits), 4)])

# # class Trivium:
# #     def __init__(self, key, iv):
# #         self.state = [0] * 288
# #         key_bits = hex_to_bits(key)
# #         iv_bits = hex_to_bits(iv)
        
# #         # Initialize the state
# #         for i in range(80):
# #             self.state[i] = int(key_bits[i])
# #             self.state[i + 92] = int(iv_bits[i])
# #         self.state[285] = self.state[286] = self.state[287] = 1
        
# #         # Warm-up phase (initialize state through cycling)
# #         for _ in range(4 * 288):
# #             t1 = self.state[65] ^ self.state[90] & self.state[91] ^ self.state[92] ^ self.state[170]
# #             t2 = self.state[161] ^ self.state[174] & self.state[175] ^ self.state[176] ^ self.state[263]
# #             t3 = self.state[242] ^ self.state[285] & self.state[286] ^ self.state[287] ^ self.state[68]
            
# #             self.state[0:93] = [t3] + self.state[0:92]
# #             self.state[93:177] = [t1] + self.state[93:176]
# #             self.state[177:288] = [t2] + self.state[177:287]

# #     def _update(self):
# #         t1 = self.state[65] ^ self.state[92]
# #         t2 = self.state[161] ^ self.state[176]
# #         t3 = self.state[242] ^ self.state[287]
# #         z = t1 ^ t2 ^ t3
# #         t1 ^= (self.state[90] & self.state[91]) ^ self.state[170]
# #         t2 ^= (self.state[174] & self.state[175]) ^ self.state[263]
# #         t3 ^= (self.state[285] & self.state[286]) ^ self.state[68]
# #         self.state = [t3] + self.state[:287]
# #         self.state[93] = t1
# #         self.state[177] = t2
# #         return z

# #     def generate_keystream(self, length):
# #         return ''.join([str(self._update()) for _ in range(length)][::-1])

# # def trivium_cipher(key, iv):
# #     cipher = Trivium(key, iv)
# #     keystream = cipher.generate_keystream(512)
# #     return bits_to_hex(keystream)

# # # Test vectors
# # key1 = "00000000000000000000"
# # iv1 = "00000000000000000000"
# # key2 = "80000000000000000000"
# # iv2 = "00000000000000000000"

# # print("Test Vector 1:")
# # print(f"Key = 0x{key1}")
# # print(f"IV = 0x{iv1}")
# # print(f"Keystream = 0x{trivium_cipher(key1, iv1).upper()}")

# # print("\nTest Vector 2:")
# # print(f"Key = 0x{key2}")
# # print(f"IV = 0x{iv2}")
# # print(f"Keystream = 0x{trivium_cipher(key2, iv2).upper()}")


# import numpy as np

# # Function to reverse the bits in a byte
# def reverse_bits_in_byte(byte):
#     return '{:08b}'.format(int(byte, 16))[::-1]

# # Function to convert hex string to reversed bits
# def hex_to_bits(hex_string):
#     return ''.join([reverse_bits_in_byte(hex_string[i:i+2]) for i in range(0, len(hex_string), 2)])

# # Function to convert bits back to hex
# def bits_to_hex(bits):
#     hex_string = ''
#     for i in range(0, len(bits), 4):
#         hex_string += hex(int(bits[i:i+4], 2))[2:]
#     return hex_string

# # Trivium Cipher Class
# class Trivium:
#     def __init__(self, key, iv):
#         self.state = [0] * 288
#         key_bits = hex_to_bits(key)
#         iv_bits = hex_to_bits(iv)
        
#         # Initialize the state
#         for i in range(80):
#             self.state[i] = int(key_bits[i])
#             self.state[i + 93] = int(iv_bits[i])
#         self.state[285] = self.state[286] = self.state[287] = 1
        
#         # Warm-up phase (initialize state through cycling)
#         for _ in range(4 * 288):
#             t1 = self.state[65] ^ self.state[90] & self.state[91] ^ self.state[92] ^ self.state[170]
#             t2 = self.state[161] ^ self.state[174] & self.state[175] ^ self.state[176] ^ self.state[263]
#             t3 = self.state[242] ^ self.state[285] & self.state[286] ^ self.state[287] ^ self.state[68]
            
#             self.state[0:93] = [t3] + self.state[0:92]
#             self.state[93:177] = [t1] + self.state[93:176]
#             self.state[177:288] = [t2] + self.state[177:287]

#     def _update(self):
#         t1 = self.state[65] ^ self.state[92]
#         t2 = self.state[161] ^ self.state[176]
#         t3 = self.state[242] ^ self.state[287]
#         z = t1 ^ t2 ^ t3
#         t1 ^= (self.state[90] & self.state[91]) ^ self.state[170]
#         t2 ^= (self.state[174] & self.state[175]) ^ self.state[263]
#         t3 ^= (self.state[285] & self.state[286]) ^ self.state[68]
#         self.state = [t3] + self.state[:287]
#         self.state[93] = t1
#         self.state[177] = t2
#         return z

#     def generate_keystream(self, length):
#         return ''.join([str(self._update()) for _ in range(length)])

# # Function to run Trivium cipher
# def trivium_cipher(key, iv):
#     cipher = Trivium(key, iv)
#     keystream = cipher.generate_keystream(512)
#     return bits_to_hex(keystream)

# # Test vectors
# key1 = "00000000000000000000"
# iv1 = "00000000000000000000"
# key2 = "80000000000000000000"
# iv2 = "00000000000000000000"

# print("Test Vector 1:")
# print(f"Key = 0x{key1}")
# print(f"IV = 0x{iv1}")
# print(f"Keystream = 0x{trivium_cipher(key1, iv1).upper()}")

# print("\nTest Vector 2:")
# print(f"Key = 0x{key2}")
# print(f"IV = 0x{iv2}")
# print(f"Keystream = 0x{trivium_cipher(key2, iv2).upper()}")
