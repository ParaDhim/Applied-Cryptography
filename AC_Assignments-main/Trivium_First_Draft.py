class triviumCipher:
    def __init__(self, Key, Initial_Value):
        # Initialize the state and other parameters
        self.state = None
        self.counter = 0
        self.key = Key
        self.iv = Initial_Value

        # Initialize state array
        init_list = list(map(int, list(self.key)))  # Convert key to list of integers
        init_list += [0] * 20  # Add 20 zeros
        init_list += list(map(int, list(self.iv)))  # Convert IV to list of integers
        init_list += [0] * 4  # Add 4 zeros
        init_list += [0] * 108  # Add 108 zeros
        init_list += [1, 1, 1]  # Add three ones
        self.state = init_list  # Set the internal state

        # Perform initialization steps to prepare state
        # Perform 4 full cycles of key stream generation to drop initial output
        for _ in range(4 * 288):
            self.generator()

    def keyStream_gen(self):
        # Generator function to yield key stream bits
        while self.counter < 2 ** 64:
            self.counter += 1  # Increment counter
            yield self.generator()  # Yield the result of generator()

    def generator(self):
        # Generate a single key stream bit and update the internal state
        t_1 = self.state[65] ^ self.state[92]  # Compute t_1 as XOR of state bits
        t_2 = self.state[168] ^ self.state[183]  # Compute t_2 as XOR of state bits
        t_3 = self.state[249] ^ self.state[294]  # Compute t_3 as XOR of state bits

        out = t_1 ^ t_2 ^ t_3  # Compute the output bit as XOR of t_1, t_2, t_3

        # Compute new state bits based on current state
        s_1 = (self.state[90] & self.state[91]) ^ self.state[177] ^ t_1
        s_2 = (self.state[181] & self.state[182]) ^ self.state[270] ^ t_2
        s_3 = (self.state[292] & self.state[293]) ^ self.state[68] ^ t_3

        # Rotate state left by 1 position
        self.state = [self.state[-1]] + self.state[:-1]

        # Update specific state bits
        self.state[0] = s_3
        self.state[100] = s_1
        self.state[184] = s_2

        return out  # Return the generated bit


def hexToBytes(s):
    # Convert a hexadecimal string to a list of byte values
    return [int(s[i:i + 2], 16) for i in range(0, len(s), 2)]


def bitsToHex(b):
    # Convert a list of bits to a hexadecimal string
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)]) for i in range(0, len(b), 8)])


def hexToBits(s):
    # Convert a hexadecimal string to a list of bits
    return [(b >> i) & 1 for b in hexToBytes(s) for i in range(8)]


def format_keyStream(hex_string, chunk_size=4, chunks_per_line=8):
    # Format the key stream for better readability
    hex_string = hex_string.replace(" ", "").upper()  # Clean up and uppercase the string

    # Split into chunks of the specified size
    chunks = [hex_string[i:i + chunk_size] for i in range(0, len(hex_string), chunk_size)]

    # Format chunks with spaces
    formatted_chunks = [f"{chunk}" for chunk in chunks]

    # Group chunks into lines
    lines = [' '.join(formatted_chunks[i:i + chunks_per_line]) for i in
             range(0, len(formatted_chunks), chunks_per_line)]

    # Join lines with new lines
    formatted_string = '\n'.join(lines)
    return formatted_string


def format_keyStreamE(hex_string, chunk_size=4, chunks_per_line=8):
    # Alternate formatting function for key stream
    chunks = [hex_string[i:i + chunk_size] for i in range(0, len(hex_string), chunk_size)]

    # Group chunks into lines
    lines = [' '.join(chunks[i:i + chunks_per_line]) for i in range(0, len(chunks), chunks_per_line)]

    # Join lines with new lines
    formatted_string = '\n'.join(lines)

    return formatted_string


# Test cases to validate the implementation
test_cases = [
    {
        'key': "00000000000000000000",
        'iv': "00000000000000000000",
        'expected_keyStream': "FBE0 BF26 5859 051B 517A 2E4E 239F C97F 5632 0316 1907 CF2D E7A8 790F A1B2 E9CD F752 "
                              "9203 0268 B738 2B4C 1A75 9AA2 599A 2855 4998 6E74 8059 0380 1A4C B5A5 D4F2 "
    },
    {
        'key': "80000000000000000000",
        'iv': "00000000000000000000",
        'expected_keyStream': "38EB 86FF 730D 7A9C AF8D F13A 4420 540D BB7B 6514 64C8 7501 5520 41C2 49F2 9A64 D2FB "
                              "F515 6109 21EB E06C 8F92 CECF 7F80 98FF 20CC CC6A 62B9 7BE8 EF74 54FC 80F9 "
    }
]

# Loop through each test case
for case in test_cases:
    key = case['key']  # Retrieve key
    iv = case['iv']  # Retrieve IV
    expected_keyStream = case['expected_keyStream']  # Retrieve expected key stream

    # Print the test case details
    print(f"\nTesting Key: {key}")
    print(f"Testing IV:  {iv}")

    # Convert key and IV to bit lists
    KEY = hexToBits(key)[::-1]
    IV = hexToBits(iv)[::-1]

    # Create Trivium cipher instance
    trivium = triviumCipher(KEY, IV)

    # Retrieve the generator method
    next_key_bit = trivium.keyStream_gen().__next__

    # Generate 512 key stream bits
    keyStream = [next_key_bit() for _ in range(512)]
    keyStream_hex = bitsToHex(keyStream)  # Convert bits to hex
    gen_st = ' '.join(keyStream_hex[i:i + 2 * 2] for i in range(0, len(keyStream_hex), 2 * 2))
    expected_keyStream1 = format_keyStreamE(expected_keyStream.replace(" ", ""))

    # Print expected key stream
    print("Expected key stream:-")
    print(f"{expected_keyStream1}")
    print()

    # Format and print the generated key stream
    keyStream_formatted = format_keyStream(keyStream_hex)
    print("Generated key stream:-")
    print(f"{keyStream_formatted}")

    # Compare generated key stream with expected key stream
    if keyStream_hex.upper() == expected_keyStream.upper().replace(' ', ''):
        print("Test passed!")  # Print if test is successful
    else:
        print("Test failed.")  # Print if test fails

# Uncomment below to test additional cases
# print()
# print("ANY OTHER TEST CASE:")
# key_test = input("KEY:")
# iv_test = input("IV:")
#
# KEY = hexToBits(key_test)[::-1]
# IV = hexToBits(iv_test)[::-1]
# trivium = Trivium(KEY, IV)
# next_key_bit = trivium.keyStream_gen().__next__
# keyStream = [next_key_bit() for _ in range(512)]
# keyStream_hex = bitsToHex(keyStream)
# gen_st = ' '.join(keyStream_hex[i:i + 2 * 2] for i in range(0, len(keyStream_hex), 2 * 2))
# keyStream_formatted = format_keyStream(keyStream_hex)
# print()
# print("Generated key stream:-")
# print(f"{keyStream_formatted}")
