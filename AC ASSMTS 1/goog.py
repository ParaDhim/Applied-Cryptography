import numpy as np

class Trivium:
    def __init__(self, key_input, IV_input):
        self.key_input = key_input
        self.IV_input = IV_input
        self.state = self.initialize_state()

    def initialize_state(self):
        # Convert key and IV inputs to lists of integers
        eighty_bit_key = [int(bit) for bit in self.key_input]
        initial_value = [int(bit) for bit in self.IV_input]

        # Create the last portion of the initial state bits
        last_initial_bits = np.append(np.zeros(108, dtype=int), [1, 1, 1])
        last_initial_bits = list(last_initial_bits)

        # Create the zero-padded parts
        first_zeros = np.zeros(13, dtype=int)
        second_zeros = np.zeros(4, dtype=int)

        # Convert zero arrays to lists
        first_zeros = list(first_zeros)
        second_zeros = list(second_zeros)

        # Append zero-padding to the key and IV
        first_93_bits = np.append(eighty_bit_key, first_zeros)
        second_set_of_bits = np.append(initial_value, second_zeros)
        first_93_bits = list(first_93_bits)
        second_set_of_bits = list(second_set_of_bits)

        # Combine all parts to create the initial state
        first_177_bits = np.append(first_93_bits, second_set_of_bits)
        first_177_bits = list(first_177_bits)
        initial_state_bits = np.append(first_177_bits, last_initial_bits)
        initial_state_bits = list(initial_state_bits)

        return initial_state_bits

    def cycle(self):
        t = [0, 0, 0]

        # Compute the intermediate bits
        t[0] = (self.state[65]) ^ ((self.state[90]) & (self.state[91])) ^ (self.state[92]) ^ (self.state[170])
        t[1] = (self.state[161]) ^ ((self.state[174]) & (self.state[175])) ^ (self.state[176]) ^ (self.state[263])
        t[2] = (self.state[242]) ^ ((self.state[285]) & (self.state[286])) ^ (self.state[287]) ^ (self.state[68])

        # Update state
        state_93 = [t[2]] + self.state[:92]
        state_94_177 = [t[0]] + self.state[93:176]
        state_178_288 = [t[1]] + self.state[177:287]

        self.state = state_93 + state_94_177 + state_178_288

        return t[0] ^ t[1] ^ t[2]

    def generate_keystream(self, length):
        keystream = []
        for _ in range(length):
            keystream.append(self.cycle())
        return keystream

if __name__ == '__main__':
    key_input = "00000000000000000000"
    IV_input = "00000000000000000000"

    # Initialize the Trivium cipher with key and IV
    trivium = Trivium(key_input=key_input, IV_input=IV_input)
    
    # Generate 512 bits of keystream
    keystream = trivium.generate_keystream(512)
    
    # Convert keystream to string
    keystream_str = ''.join(map(str, keystream))
    
    print("Generated keystream (512 bits):", keystream_str)
