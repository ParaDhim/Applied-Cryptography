def hex_to_bits(hex_string):
    return ''.join([bin(int(c, 16))[2:].zfill(4) for c in hex_string])

def flip_bit_order(bits):
    """Flip the bit order within each byte."""
    return ''.join(bits[i:i + 8][::-1] for i in range(0, len(bits), 8))

def bits_to_hex(bits):
    return ''.join([hex(int(bits[i:i + 4], 2))[2:] for i in range(0, len(bits), 4)])

class Trivium:
    def __init__(self, key, iv):
        self.state = [0] * 288
        key_bits = hex_to_bits(key)
        iv_bits = hex_to_bits(iv)
        
        # Flip bit order within each byte of key and IV
        key_bits_flipped = flip_bit_order(key_bits)
        iv_bits_flipped = flip_bit_order(iv_bits)

        # Initialize the state
        for i in range(80):
            self.state[i] = int(key_bits_flipped[i])
            self.state[i + 92] = int(iv_bits_flipped[i])
        self.state[285] = self.state[286] = self.state[287] = 1

        for _ in range(4 * 288):
            t1 = self.state[65] ^ (self.state[90] & self.state[91]) ^ self.state[92] ^ self.state[170]
            t2 = self.state[161] ^ (self.state[174] & self.state[175]) ^ self.state[176] ^ self.state[263]
            t3 = self.state[242] ^ (self.state[285] & self.state[286]) ^ self.state[287] ^ self.state[68]

            self.state[0:93] = [t3] + self.state[0:92]
            self.state[93:177] = [t1] + self.state[93:176]
            self.state[177:288] = [t2] + self.state[177:287]

    def _update(self):
        t1 = self.state[65] ^ self.state[92]
        t2 = self.state[161] ^ self.state[176]
        t3 = self.state[242] ^ self.state[287]
        z = t1 ^ t2 ^ t3
        t1 ^= (self.state[90] & self.state[91]) ^ self.state[170]
        t2 ^= (self.state[174] & self.state[175]) ^ self.state[263]
        t3 ^= (self.state[285] & self.state[286]) ^ self.state[68]
        self.state = [t3] + self.state[:287]
        self.state[93] = t1
        self.state[177] = t2
        return z

    def generate_keystream(self, length):
        return ''.join([str(self._update()) for _ in range(length)][::-1])

def trivium_cipher(key, iv):
    cipher = Trivium(key, iv)
    keystream = cipher.generate_keystream(512)  # Generate 512 bits
    return bits_to_hex(keystream)

# Test vectors
key1 = "00000000000000000000"
iv1 = "00000000000000000000"
key2 = "80000000000000000000"
iv2 = "00000000000000000000"

print("Test Vector 1:")
print(f"Key = 0x{key1}")
print(f"IV = 0x{iv1}")
print(f"Keystream = 0x{trivium_cipher(key1, iv1).upper()}")

print("\nTest Vector 2:")
print(f"Key = 0x{key2}")
print(f"IV = 0x{iv2}")
print(f"Keystream = 0x{trivium_cipher(key2, iv2).upper()}")
