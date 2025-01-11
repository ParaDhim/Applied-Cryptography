def trivium_keystream(key, iv, rounds):
    # Initialize the internal state
    state = [0] * 288
    for i in range(96):
        state[i] = key[i]
    for i in range(96):
        state[i + 96] = iv[i]

    # Initialize the keystream
    keystream = []

    # Generate the keystream
    for i in range(rounds):
        # Calculate the output bit
        output = state[65] ^ state[92] ^ state[161] ^ state[176] ^ state[208] ^ state[240] ^ state[272]

        # Update the internal state
        state = [state[1]] + state[:287]
        state[95] = state[65] ^ state[92] ^ state[161] ^ state[176] ^ state[208] ^ state[240] ^ state[272]
        state[110] = state[65] ^ state[92] ^ state[161] ^ state[176] ^ state[208] ^ state[240] ^ state[272]
        state[143] = state[65] ^ state[92] ^ state[161] ^ state[176] ^ state[208] ^ state[240] ^ state[272]
        state[278] = state[65] ^ state[92] ^ state[161] ^ state[176] ^ state[208] ^ state[240] ^ state[272]

        # Append the output bit to the keystream
        keystream.append(output)

    return keystream

# Example usage:
key = [1] * 96  # Replace with your key
iv = [0] * 96   # Replace with your IV
rounds = 128   # Number of rounds
keystream = trivium_keystream(key, iv, rounds)
print(keystream)
