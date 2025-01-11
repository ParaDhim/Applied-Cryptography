from collections import deque
def bits_to_hex(b):
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)]) for i in range(0, len(b), 8)])


class Trivium:
    def __init__(self, key, iv):
        # Convert key and IV from hex to bit list
        key_bits = hex_to_bit_list(key)
        iv_bits = hex_to_bit_list(iv)
        
        # Initialize registers
        init_regs = key_bits + [0] * 13 + iv_bits + [0] * 4 + [0] * 108 + [1, 1, 1]
        
        # Create the state using a deque (as it has a rotation method)
        self.state = deque(init_regs)

        # Warm-up phase, which includes 4 full cycles of the state
        for _ in range(1152):
            self.gen_keystream()

    def gen_keystream(self):
        t1 = self.state[65] ^ self.state[92]
        t2 = self.state[161] ^ self.state[176]
        t3 = self.state[242] ^ self.state[287]
        
        a1 = self.state[90] & self.state[91]
        a2 = self.state[174] & self.state[175]
        a3 = self.state[285] & self.state[286]

        zi = t1 ^ t2 ^ t3

        s1 = t1 ^ a1 ^ self.state[170]
        s2 = t2 ^ a2 ^ self.state[263]
        s3 = t3 ^ a3 ^ self.state[68]

        self.state.rotate(1)

        self.state[0] = s3
        self.state[93] = s1
        self.state[177] = s2

        return zi

# Example usage
p = Trivium("80000000000000000000", "00000000000000000000")
check = ""
for _ in range(512):
    check += str(p.gen_keystream())
print(bit_list_to_hex(check)[::-1])