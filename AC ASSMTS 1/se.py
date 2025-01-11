def hex_to_bits(hex_string):
    return [int(bin(int(hex_string[i:i+2], 16))[2:].zfill(8)[j]) for i in range(0, len(hex_string), 2) for j in range(8)]

def bits_to_hex(bits):
    return ''.join([f'{int("".join(map(str, bits[i:i+8])), 2):02X}' for i in range(0, len(bits), 8)])

def initialize_state(key, iv):
    state = [0] * 288
    key_bits = hex_to_bits(key)
    iv_bits = hex_to_bits(iv)
    
    state[:80] = key_bits
    state[93:93+80] = iv_bits
    state[285:288] = [1, 1, 1]
    
    return state

def trivium_keystream(key, iv, num_bits):
    state = initialize_state(key, iv)
    keystream = []

    for _ in range(4 * 288):  # Warm-up phase
        t1 = state[65] ^ state[92]
        t2 = state[161] ^ state[176]
        t3 = state[242] ^ state[287]
        
        t1 ^= state[90] & state[91]
        t2 ^= state[174] & state[175]
        t3 ^= state[285] & state[286]
        
        state = [t3] + state[:287]
        state[93] = t1
        state[177] = t2

    for _ in range(num_bits):
        t1 = state[65] ^ state[92]
        t2 = state[161] ^ state[176]
        t3 = state[242] ^ state[287]
        
        z = t1 ^ t2 ^ t3
        
        t1 ^= state[90] & state[91]
        t2 ^= state[174] & state[175]
        t3 ^= state[285] & state[286]
        
        state = [t3] + state[:287]
        state[93] = t1
        state[177] = t2
        
        keystream.append(z)

    return keystream

def generate_keystream(key, iv, num_bits=512):
    keystream = trivium_keystream(key, iv, num_bits)
    return bits_to_hex(keystream)

# Test vectors
test_vectors = [
    ("00000000000000000000", "00000000000000000000"),
    ("80000000000000000000", "00000000000000000000")
]

for key, iv in test_vectors:
    print(f"Key = 0x{key}")
    print(f"IV = 0x{iv}")
    keystream = generate_keystream(key, iv)
    print(f"Keystream = 0x{keystream}")
    print()