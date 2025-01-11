class Trivium:
    def __init__(self, key, iv):
        self.state = [0] * 288
        
        # Initialize the state with key and IV
        for i in range(80):
            self.state[i] = int(key[i])
            self.state[i + 93] = int(iv[i])
        
        # Set the last three bits to 1
        self.state[285] = self.state[286] = self.state[287] = 1
        
        # Key and IV setup
        for _ in range(4 * 288):
            t1 = self.state[65] ^ (self.state[90] & self.state[91]) ^ self.state[92] ^ self.state[170]
            t2 = self.state[161] ^ (self.state[174] & self.state[175]) ^ self.state[176] ^ self.state[263]
            t3 = self.state[242] ^ (self.state[285] & self.state[286]) ^ self.state[287] ^ self.state[68]
            
            self.state = [t3] + self.state[:92] + [t1] + self.state[93:176] + [t2] + self.state[177:287]

    def _update(self):
        t1 = self.state[65] ^ self.state[92]
        t2 = self.state[161] ^ self.state[176]
        t3 = self.state[242] ^ self.state[287]
        
        z = t1 ^ t2 ^ t3
        
        t1 = t1 ^ (self.state[90] & self.state[91]) ^ self.state[170]
        t2 = t2 ^ (self.state[174] & self.state[175]) ^ self.state[263]
        t3 = t3 ^ (self.state[285] & self.state[286]) ^ self.state[68]
        
        self.state = [t3] + self.state[:287]
        self.state[93] = t1
        self.state[177] = t2
        
        return z

    def generate_keystream(self, num_bits):
        return [self._update() for _ in range(num_bits)]

def hex_to_binary(hex_string):
    return ''.join([bin(int(char, 16))[2:].zfill(4) for char in hex_string])

def binary_to_hex(binary_string):
    return ''.join([hex(int(binary_string[i:i+4], 2))[2:].upper() for i in range(0, len(binary_string), 4)])

def generate_keystream(key, iv, num_bits=512):
    binary_key = hex_to_binary(key)
    binary_iv = hex_to_binary(iv)
    trivium = Trivium(binary_key, binary_iv)
    keystream_bits = trivium.generate_keystream(num_bits)
    keystream_binary = ''.join(map(str, keystream_bits))
    return binary_to_hex(keystream_binary)

# Test vectors
test_vectors = [
    ("00000000000000000000", "00000000000000000000"),
    ("80000000000000000000", "00000000000000000000")
]

print("In this assignment you need to implement the Trivium Cipher.")
print("The formal description of Trivium Cipher has been taught in the class and can be found here - https://www.ecrypt.eu.org/stream/p3ciphers/trivium/trivium_p3.pdf")
print("In this implementation you need to generate 512 bits of keystream while taking the key and IV as the input.")
print("The test vectors are (the values are in hex):")

for key, iv in test_vectors:
    print(f"• Key = 0x{key}")
    print(f"  IV = 0x{iv}")
    keystream = generate_keystream(key, iv)
    print(f"  keystream = 0x{' '.join([keystream[i:i+4] for i in range(0, len(keystream), 4)])}")
    print()