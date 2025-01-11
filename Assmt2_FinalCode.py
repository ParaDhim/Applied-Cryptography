class Trivium:
    def __init__(self, key, iv):
        """Initialize the Trivium cipher with key and IV."""
        self.state = None
        self.counter = 0
        self.key = key
        self.iv = iv

        # Initialize state
        init_list = list(map(int, list(self.key)))
        init_list += [0] * 20
        init_list += list(map(int, list(self.iv)))
        init_list += [0] * 4
        init_list += [0] * 108
        init_list += [1, 1, 1]
        self.state = init_list

        # Do 4 full cycles, drop output
        for _ in range(4 * 288):
            self._gen_stream()

    def keystream(self):
        """Output keystream."""
        while self.counter < 2**64:
            self.counter += 1
            yield self._gen_stream()

    def _gen_stream(self):
        """Generate Trivium's keystream."""
        t_1 = self.state[65] ^ self.state[92]
        t_2 = self.state[168] ^ self.state[183]
        t_3 = self.state[249] ^ self.state[294]

        out = t_1 ^ t_2 ^ t_3

        s_1 = (self.state[90] & self.state[91]) ^ self.state[177] ^ t_1
        s_2 = (self.state[181] & self.state[182]) ^ self.state[270] ^ t_2
        s_3 = (self.state[292] & self.state[293]) ^ self.state[68] ^ t_3

        # Rotate state left by 1
        self.state = [self.state[-1]] + self.state[:-1]

        self.state[0] = s_3
        self.state[100] = s_1
        self.state[184] = s_2

        return out

def hexToBytes(s):
    return [int(s[i:i + 2], 16) for i in range(0, len(s), 2)]

def bitsToHex(b):
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)]) for i in range(0, len(b), 8)])

def hexToBits(s):
    return [(b >> i) & 1 for b in hexToBytes(s) for i in range(8)]

def format_keystream(hex_string, chunk_size=4, chunks_per_line=8):
    # Remove spaces and convert the string to uppercase
    hex_string = hex_string.replace(" ", "").upper()
    
    # Split into chunks of the specified chunk size
    chunks = [hex_string[i:i + chunk_size] for i in range(0, len(hex_string), chunk_size)]
    
    # Format chunks with spaces
    formatted_chunks = [f"{chunk}" for chunk in chunks]
    
    # Group chunks into lines
    lines = [ ' '.join(formatted_chunks[i:i + chunks_per_line]) for i in range(0, len(formatted_chunks), chunks_per_line)]
    
    # Join lines with new lines
    formatted_string = '\n'.join(lines)
    
    return formatted_string

def format_keystreamE(hex_string, chunk_size=4, chunks_per_line=8):
    # Split into chunks of the specified chunk size
    chunks = [hex_string[i:i + chunk_size] for i in range(0, len(hex_string), chunk_size)]
    
    # Group chunks into lines
    lines = [ ' '.join(chunks[i:i + chunks_per_line]) for i in range(0, len(chunks), chunks_per_line)]
    
    # Join lines with new lines
    formatted_string = '\n'.join(lines)
    
    return formatted_string

# Test cases
test_cases = [
    {
        'key': "00000000000000000000",
        'iv': "00000000000000000000",
        'expected_keystream': "FBE0 BF26 5859 051B 517A 2E4E 239F C97F 5632 0316 1907 CF2D E7A8 790F A1B2 E9CD F752 9203 0268 B738 2B4C 1A75 9AA2 599A 2855 4998 6E74 8059 0380 1A4C B5A5 D4F2"
    },
    {
        'key': "80000000000000000000",
        'iv': "00000000000000000000",
        'expected_keystream': "38EB 86FF 730D 7A9C AF8D F13A 4420 540D BB7B 6514 64C8 7501 5520 41C2 49F2 9A64 D2FB F515 6109 21EB E06C 8F92 CECF 7F80 98FF 20CC CC6A 62B9 7BE8 EF74 54FC 80F9"
    }
]

for case in test_cases:
    key = case['key']
    iv = case['iv']
    expected_keystream = case['expected_keystream']
    # format_keystream(expected_keystream.replace(" ", ""))
    
    print(f"\nTesting Key: {key}")
    print(f"Testing IV:  {iv}")

    KEY = hexToBits(key)[::-1]
    IV = hexToBits(iv)[::-1]

    trivium = Trivium(KEY, IV)
    next_key_bit = trivium.keystream().__next__
    keystream = [next_key_bit() for _ in range(512)]
    keystream_hex = bitsToHex(keystream)
    gen_st = ' '.join(keystream_hex[i:i + 2 * 2] for i in range(0, len(keystream_hex), 2 * 2))
    expected_keystream1 = format_keystreamE(expected_keystream.replace(" ", ""))
    # print(f"Generated keystream: {gen_st}")
    print("Expected keystream:-")
    print(f"{expected_keystream1}")
    print()
    # Print keystream in chunks of 8 bytes
    # keystream_formatted = ' '.join(keystream_hex[i:i + 2 * 2] for i in range(0, len(keystream_hex), 2 * 2))
    keystream_formatted = format_keystream(keystream_hex)
    print("Generated keystream:-")
    print(f"{keystream_formatted}")

    # Check if generated keystream matches the expected keystream
    if keystream_hex.upper() == expected_keystream.upper().replace(' ', ''):
        print("Test passed!")
    else:
        print("Test failed.")
        
        
print()
print("ANY OTHER TEST CASE:")
key_test = input("KEY:")
iv_test = input("IV:")

KEY = hexToBits(key_test)[::-1]
IV = hexToBits(iv_test)[::-1]
trivium = Trivium(KEY, IV)
next_key_bit = trivium.keystream().__next__
keystream = [next_key_bit() for _ in range(512)]
keystream_hex = bitsToHex(keystream)
gen_st = ' '.join(keystream_hex[i:i + 2 * 2] for i in range(0, len(keystream_hex), 2 * 2))
keystream_formatted = format_keystream(keystream_hex)
print()
print("Generated keystream:-")
print(f"{keystream_formatted}")


