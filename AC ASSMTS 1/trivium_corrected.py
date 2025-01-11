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
            self._gen_keystream()

    def keystream(self):
        """Output keystream."""
        while self.counter < 2**64:
            self.counter += 1
            yield self._gen_keystream()

    def _setLength(self, input_data):
        """Format input_data to 80 bits, padding with zeros if necessary."""
        input_data = "{0:080b}".format(input_data)
        if len(input_data) > 80:
            input_data = input_data[:(len(input_data) - 81):-1]
        else:
            input_data = input_data[::-1]
        return input_data

    def _gen_keystream(self):
        """Generate Trivium's keystream."""
        a_1 = self.state[90] & self.state[91]
        a_2 = self.state[181] & self.state[182]
        a_3 = self.state[292] & self.state[293]

        t_1 = self.state[65] ^ self.state[92]
        t_2 = self.state[168] ^ self.state[183]
        t_3 = self.state[249] ^ self.state[294]

        out = t_1 ^ t_2 ^ t_3

        s_1 = a_1 ^ self.state[177] ^ t_1
        s_2 = a_2 ^ self.state[270] ^ t_2
        s_3 = a_3 ^ self.state[68] ^ t_3

        # Rotate state left by 1
        self.state = [self.state[-1]] + self.state[:-1]

        self.state[0] = s_3
        self.state[100] = s_1
        self.state[184] = s_2

        return out

def hex_to_bytes(s):
    return [int(s[i:i + 2], 16) for i in range(0, len(s), 2)]

def bits_to_hex(b):
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)]) for i in range(0, len(b), 8)])

def hex_to_bits(s):
    return [(b >> i) & 1 for b in hex_to_bytes(s) for i in range(8)]

def get_next_stream_byte(next_key_bit):
    rtn = 0
    for j in range(8):
        rtn += int(next_key_bit()) << j
    return rtn

# Simulate command-line arguments
k1 = "80000000000000000000"
i1 = "00000000000000000000"
message = b"hello"

print("Key: " + k1)
print("IV:  " + i1)

KEY = hex_to_bits(k1)[::-1]
IV = hex_to_bits(i1)[::-1]

trivium = Trivium(KEY, IV)
next_key_bit = trivium.keystream().__next__
keystream = [next_key_bit() for _ in range(128)]
print("Key stream: " + bits_to_hex(keystream))

# Encrypt the message
trivium = Trivium(KEY, IV)
next_key_bit = trivium.keystream().__next__

buffer = bytearray()
for mybyte in message:
    c = get_next_stream_byte(next_key_bit)
    newbyte = (mybyte ^ c) & 0xFF
    buffer.append(newbyte)

# Reset key stream
trivium = Trivium(KEY, IV)
next_key_bit = trivium.keystream().__next__

decrypt = ''
print("\nPlaintext: ", message.decode())
print("Cipher:", ''.join([f"{b:02x}" for b in buffer]))

for mybyte in buffer:
    c = get_next_stream_byte(next_key_bit)
    newbyte = (mybyte ^ c) & 0xFF
    decrypt += chr(newbyte)

print(f"Decrypted: {decrypt}")
