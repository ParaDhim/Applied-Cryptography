def hex_to_bits(hex_string):
    return ''.join([bin(int(c, 16))[2:].zfill(4) for c in hex_string])

def bits_to_hex(bits):
    return ''.join([hex(int(bits[i:i+4], 2))[2:].upper() for i in range(0, len(bits), 4)])

class Trivium:
    def __init__(self, key, iv):
        self.state = [0] * 288
        key_bits = hex_to_bits(key).zfill(80)
        iv_bits = hex_to_bits(iv).zfill(80)
        # Initialize the state
        for i in range(80):
            self.state[i] = int(key_bits[i])
            self.state[i + 93] = int(iv_bits[i])
        self.state[285] = self.state[286] = self.state[287] = 1
        # Warm-up
        for _ in range(4 * 288):
            self._update()

    def _update(self):
        t1 = self.state[65] ^ self.state[92]
        t2 = self.state[161] ^ self.state[176]
        t3 = self.state[242] ^ self.state[287]
        z = t1 ^ t2 ^ t3
        t1 ^= (self.state[90] & self.state[91]) ^ self.state[170]
        t2 ^= (self.state[174] & self.state[175]) ^ self.state[263]
        t3 ^= (self.state[285] & self.state[286]) ^ self.state[68]
        self.state = self.state[1:] + [t3]
        self.state[93] = t1
        self.state[177] = t2
        return z

    def generate_keystream(self, length):
        return ''.join([str(self._update()) for _ in range(length)])

def trivium_cipher(key, iv):
    cipher = Trivium(key, iv)
    keystream = cipher.generate_keystream(512)
    hex_stream = bits_to_hex(keystream)
    return ' '.join([hex_stream[i:i+4] for i in range(0, len(hex_stream), 4)])

def print_keystream(keystream):
    lines = [keystream[i:i+40] for i in range(0, len(keystream), 40)]
    print('\n'.join(lines))

# Test vectors
key1 = "00000000000000000000"
iv1 = "00000000000000000000"
key2 = "80000000000000000000"
iv2 = "00000000000000000000"

print("Test Vector 1:")
print("Key =", "0x" + key1)
print("IV =", "0x" + iv1)
print("keystream = 0x")
print_keystream(trivium_cipher(key1, iv1))

print("\nTest Vector 2:")
print("Key =", "0x" + key2)
print("IV =", "0x" + iv2)
print("keystream = 0x")
print_keystream(trivium_cipher(key2, iv2))