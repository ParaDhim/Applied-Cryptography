def generate_trivium_keystream(key, iv, num_bytes):
    # Convert key and IV to bit arrays
    state = [int(b) for byte in key for b in f'{byte:08b}']  # Key bits
    state += [0] * 13  # 13 zeros
    state += [int(b) for byte in iv for b in f'{byte:08b}']  # IV bits
    state += [0] * 112  # 112 zeros
    state += [1, 1, 1]  # 3 ones
    
    if len(state) != 288:
        raise ValueError("Initial state length must be 288 bits")

    # Initialize the state (4 full cycles)
    for _ in range(4 * 288):
        t1 = state[65] ^ state[92]
        t2 = state[161] ^ state[176]
        t3 = state[242] ^ state[287]
        
        t1 ^= (state[90] & state[91]) ^ state[170]
        t2 ^= (state[174] & state[175]) ^ state[263]
        t3 ^= (state[285] & state[286]) ^ state[68]
        
        state = [t3] + state[:92] + [t1] + state[94:176] + [t2] + state[178:287]

    # Generate keystream
    keystream = []
    for _ in range(num_bytes):
        keystream_byte = 0
        for _ in range(8):
            t1 = state[65] ^ state[92]
            t2 = state[161] ^ state[176]
            t3 = state[242] ^ state[287]
            
            z = t1 ^ t2 ^ t3
            keystream_byte = (keystream_byte << 1) | z
            
            t1 ^= (state[90] & state[91]) ^ state[170]
            t2 ^= (state[174] & state[175]) ^ state[263]
            t3 ^= (state[285] & state[286]) ^ state[68]
            
            state = [t3] + state[:92] + [t1] + state[94:176] + [t2] + state[178:287]
        
        keystream.append(keystream_byte)

    return bytes(keystream)

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string.replace(" ", ""))

# Test vectors
test_vectors = [
    {
        "key": "00000000000000000000",
        "iv": "00000000000000000000",
        "expected_keystream": "FBE BF26 5859 051B 517A 24E 239F C97F 5632 0316 1907 CF2D E7A8 790F A1B2 E9CD F752 9203 0268 B738 2B4C 1A75 9AA2 599A 2855 4998 6E74 8059 0380 1A4C B5A5 D4F2"
    },
    {
        "key": "80000000000000000000",
        "iv": "00000000000000000000",
        "expected_keystream": "38EB 86FF 730D 7A9C AF8D F13A 4420 540D BB7B 6514 64C8 7501 5520 41C2 49F2 9A64 D2FB F515 6109 21EB E06C 8F92 CECF 7F80 98FF 20CC CC6A 62B9 7BE8 EF74 54FC 80F9"
    }
]

for i, vector in enumerate(test_vectors, 1):
    key = hex_to_bytes(vector["key"])
    iv = hex_to_bytes(vector["iv"])
    expected_keystream = hex_to_bytes(vector["expected_keystream"])
    
    try:
        generated_keystream = generate_trivium_keystream(key, iv, len(expected_keystream))
        
        print(f"Test Vector {i}:")
        print(f"Key: {vector['key']}")
        print(f"IV: {vector['iv']}")
        print(f"Generated Keystream: {generated_keystream.hex().upper()}")
        print(f"Expected Keystream:  {expected_keystream.hex().upper()}")
        print(f"Match: {generated_keystream == expected_keystream}")
    except ValueError as e:
        print(f"Test Vector {i} failed with error: {e}")
    print()