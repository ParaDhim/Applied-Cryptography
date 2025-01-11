class SnowV:
    def __init__(self):
        # S-box from AES
        self.SBox = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]
        self.Sigma = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        self.AesKey1 = [0, 0, 0, 0]
        self.AesKey2 = [0, 0, 0, 0]
        
        # Initialize LFSR and FSM
        self.A = [0] * 16
        self.B = [0] * 16
        self.R1 = [0] * 4
        self.R2 = [0] * 4
        self.R3 = [0] * 4

    def _make_u32(self, a, b):
        return ((a & 0xFFFF) << 16) | (b & 0xFFFF)

    def _make_u16(self, a, b):
        return ((a & 0xFF) << 8) | (b & 0xFF)

    def _rotl32(self, x, n):
        """Rotate a 32-bit integer left by n positions"""
        return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))
    
    def matrix_to_words(self, state_matrix):
        """Convert 4x4 byte matrix to array of 4 32-bit words"""
        words = [0] * 4
        for i in range(4):
            word = 0
            for j in range(4):
                # Extract byte from matrix and shift to correct position
                byte_val = int(state_matrix[j][i], 16)
                word |= (byte_val << (24 - j * 8))
            words[i] = word
        return words
    
    def words_to_matrix(self, words):
        """Convert array of 4 32-bit words back to 4x4 hex matrix"""
        matrix = [["0x00" for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                # Extract byte and convert to hex format
                byte_val = (words[i] >> (24 - j * 8)) & 0xFF
                hex_val = hex(byte_val)
                if len(hex_val) == 3:
                    hex_val = hex_val[:2] + "0" + hex_val[2]
                matrix[j][i] = hex_val
        return matrix
    
    def sub_bytes(self, state):
        """Perform SubBytes transformation
        Args:
            state: Array of 4 32-bit words representing the state
        Returns:
            List of 16 bytes after S-box substitution
        """
        sb = [0] * 16
        for i in range(4):
            for j in range(4):
                # Extract each byte and apply S-box substitution
                byte_val = (state[i] >> (j * 8)) & 0xFF
                sb[i * 4 + j] = self.SBox[byte_val]
        return sb

    def shift_rows(self, sb):
        """Perform ShiftRows transformation
        Args:
            sb: List of 16 bytes after SubBytes
        Returns:
            Array of 4 32-bit words with shifted bytes
        """
        result = [0] * 4
        for j in range(4):
            # Construct word with shifted bytes:
            # - Byte 0: No shift (0)
            # - Byte 1: Shift by 1 (5)
            # - Byte 2: Shift by 2 (10)
            # - Byte 3: Shift by 3 (15)
            result[j] = (sb[(j * 4 + 0) % 16] << 24) | \
                       (sb[(j * 4 + 5) % 16] << 0) | \
                       (sb[(j * 4 + 10) % 16] << 8) | \
                       (sb[(j * 4 + 15) % 16] << 16)
        return result

    def mix_columns(self, shifted_state):
        """Perform MixColumns transformation
        Args:
            shifted_state: Array of 4 32-bit words after ShiftRows
        Returns:
            Array of 4 32-bit words after MixColumns
        """
        result = [0] * 4
        for j in range(4):
            w = shifted_state[j]
            # Optimized implementation using rotations and XOR operations
            t = self._rotl32(w, 16) ^ \
                ((w << 1) & 0xfefefefe) ^ \
                (((w >> 7) & 0x01010101) * 0x1b)
            result[j] = w ^ t ^ self._rotl32(t, 8)
        return result

    def add_round_key(self, state, round_key):
        """Perform AddRoundKey transformation
        Args:
            state: Array of 4 32-bit words representing the current state
            round_key: Array of 4 32-bit words representing the round key
        Returns:
            Array of 4 32-bit words after XORing with round key
        """
        return [state[i] ^ round_key[i] for i in range(4)]

    def aes_enc_round(self, state, round_key):
        """Perform one round of AES encryption
        Args:
            state: Array of 4 32-bit words representing the state
            round_key: Array of 4 32-bit words representing the round key
        Returns:
            Array of 4 32-bit words representing the transformed state
        """
        # Step 1: SubBytes
        sb = self.sub_bytes(state)
        
        # Step 2: ShiftRows
        shifted = self.shift_rows(sb)
        
        # Step 3: MixColumns
        mixed = self.mix_columns(shifted)
        
        # Step 4: AddRoundKey
        result = self.add_round_key(mixed, round_key)
        
        return result
    
    def encrypt_block(self, input_matrix, round_key_matrix):
        """Wrapper function to handle matrix-based input/output"""
        # Convert input matrix to words
        state_words = self.matrix_to_words(input_matrix)
        key_words = self.matrix_to_words(round_key_matrix)
        
        # Perform encryption round
        result_words = self.aes_enc_round(state_words, key_words)
        
        # Convert result back to matrix
        return self.words_to_matrix(result_words)


    def mul_x(self, v, c):
        if v & 0x8000:
            return ((v << 1) ^ c) & 0xFFFF
        return (v << 1) & 0xFFFF

    def mul_x_inv(self, v, d):
        if v & 0x0001:
            return ((v >> 1) ^ d) & 0xFFFF
        return (v >> 1) & 0xFFFF

    def permute_sigma(self, state):
        tmp = [0] * 16
        for i in range(16):
            tmp[i] = (state[self.Sigma[i] >> 2] >> ((self.Sigma[i] & 3) << 3)) & 0xFF
        
        for i in range(4):
            state[i] = self._make_u32(
                self._make_u16(tmp[4 * i + 3], tmp[4 * i + 2]),
                self._make_u16(tmp[4 * i + 1], tmp[4 * i])
            )
        return state

    def fsm_update(self):
        R1temp = self.R1.copy()
        
        for i in range(4):
            T2 = self._make_u32(self.A[2 * i + 1], self.A[2 * i])
            self.R1[i] = ((T2 ^ self.R3[i]) + self.R2[i]) & 0xFFFFFFFF
        
        self.R1 = self.permute_sigma(self.R1)
        self.R3 = self.aes_enc_round(self.R2, self.AesKey2)
        self.R2 = self.aes_enc_round(R1temp, self.AesKey1)

    def lfsr_update(self):
        for _ in range(8):
            u = self.mul_x(self.A[0], 0x990f) ^ self.A[1] ^ \
                self.mul_x_inv(self.A[8], 0xcc87) ^ self.B[0]
            v = self.mul_x(self.B[0], 0xc963) ^ self.B[3] ^ \
                self.mul_x_inv(self.B[8], 0xe4b1) ^ self.A[0]
            
            self.A = self.A[1:] + [u]
            self.B = self.B[1:] + [v]

    def keystream(self):
        z = bytearray(16)
        
        for i in range(4):
            T1 = self._make_u32(self.B[2 * i + 9], self.B[2 * i + 8])
            v = ((T1 + self.R1[i]) & 0xFFFFFFFF) ^ self.R2[i]
            
            z[i * 4 + 0] = (v >> 0) & 0xFF
            z[i * 4 + 1] = (v >> 8) & 0xFF
            z[i * 4 + 2] = (v >> 16) & 0xFF
            z[i * 4 + 3] = (v >> 24) & 0xFF
        
        self.fsm_update()
        self.lfsr_update()
        return z

    def keyiv_setup(self, key, iv, is_aead_mode=0):
        # Initialize LFSR state
        for i in range(8):
            self.A[i] = self._make_u16(iv[2 * i + 1], iv[2 * i])
            self.A[i + 8] = self._make_u16(key[2 * i + 1], key[2 * i])
            self.B[i] = 0x0000
            self.B[i + 8] = self._make_u16(key[2 * i + 17], key[2 * i + 16])

        # Set AEAD constants if needed
        if is_aead_mode == 1:
            self.B[0:8] = [0x6C41, 0x7865, 0x6B45, 0x2064, 
                          0x694A, 0x676E, 0x6854, 0x6D6F]

        # Initialize FSM state
        self.R1 = [0] * 4
        self.R2 = [0] * 4
        self.R3 = [0] * 4

        # Initialization rounds
        for i in range(16):
            z = self.keystream()
            for j in range(8):
                self.A[j + 8] ^= self._make_u16(z[2 * j + 1], z[2 * j])
            
            if i == 14:
                for j in range(4):
                    self.R1[j] ^= self._make_u32(
                        self._make_u16(key[4 * j + 3], key[4 * j + 2]),
                        self._make_u16(key[4 * j + 1], key[4 * j + 0])
                    )
            if i == 15:
                for j in range(4):
                    self.R1[j] ^= self._make_u32(
                        self._make_u16(key[4 * j + 19], key[4 * j + 18]),
                        self._make_u16(key[4 * j + 17], key[4 * j + 16])
                    )
import time
import os

def measure_encryption_time(snow, plaintext_size):
    # Generate random plaintext of the given size (in bytes)
    plaintext = os.urandom(plaintext_size // 8)  # Convert bits to bytes

    # Pad plaintext to a multiple of 16 bytes
    padded_plaintext = plaintext + b"\x00" * (16 - len(plaintext) % 16)

    # Measure encryption time
    start_time = time.perf_counter()

    ciphertext = bytearray(len(padded_plaintext))
    for i in range(0, len(padded_plaintext), 16):
        keystream = snow.keystream()  # Generate a block of keystream
        for j in range(16):
            ciphertext[i + j] = padded_plaintext[i + j] ^ keystream[j]

    end_time = time.perf_counter()

    encryption_time = end_time - start_time
    return encryption_time


def main():
    # Create SNOW-V instance
    snow = SnowV()

    # Test vector key and IV (example)
    key = bytes([0] * 32)
    iv = bytes([0] * 16)

    # Initialize cipher
    snow.keyiv_setup(key, iv, 0)

    # Plaintext sizes in bits
    sizes = [256, 1024, 8192]

    print("Encryption Time Comparison:")
    for size in sizes:
        # Reset the cipher for each test
        snow.keyiv_setup(key, iv, 0)

        encryption_time = measure_encryption_time(snow, size)
        print(f"Plaintext Size: {size} bits - Time: {encryption_time * 1000:.9f} milliseconds")


if __name__ == "__main__":
    main()
