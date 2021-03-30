"""
==============================================================================================================================================
|  Basic Implementation of SIMON Lightweight Block Cipher for block sizes 32, 48, 64, 96 & 128 and their corresponding key sizes. (For DFA)  |
|  Option to simulate fault injection at Round T-5 for dfa purposes. Decryption method removed as not required.                              |
|  Author: Nicholas Leu                                                                                                                      |
==============================================================================================================================================

"""


class simonfault:
    """
    z-sequence values
    """
    z = [
        [1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0,
         1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0],
        [1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1,
         1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0],
        [1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0,
         0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1],
        [1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1,
         0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1],
        [1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1,
         1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1]
    ]

    """
    PARAMETERS for SIMON cipher:
    format = block_size:{key_size:(rounds,key_words,j_value)}
    """
    parameters = {
        32: {64: (32, 4, 0)},
        48: {72: (36, 3, 0), 96: (36, 4, 1)},
        64: {96: (42, 3, 2), 128: (44, 4, 3)},
        96: {96: (52, 2, 2), 144: (54, 3, 3)},
        128: {128: (68, 2, 2), 192: (69, 3, 3), 256: (72, 4, 4)}
    }

    def __init__(self, key, block_size, key_size):

        """
        key: Int representation of the encryption key
        key_words: Int value of number of key words, m
        block_size: int value of size of block, 2n
        key_size: int value of size of key
        word_size: int value of word size, n

        """
        # Check if block_size is allowed
        try:
            self.possible_parameters = self.parameters[block_size]
            # Set up block/word size
            self.block_size = block_size
            self.word_size = int(block_size / 2)

        except KeyError:
            print('Invalid block size! Please input a block size according to the parameters allowed.')
            raise

        # check if key_size matches with block_size => if valid, set up key_size
        if key_size in self.possible_parameters:
            self.key_size = key_size

        else:
            raise Exception("Invalid key size! Please input a key size that matches the block size.")

        # set up key_words and j_value
        self.key_words = self.possible_parameters[self.key_size][1]
        self.j_value = self.possible_parameters[self.key_size][2]

        # set up rounds
        self.rounds = self.possible_parameters[self.key_size][0]

        # set up key
        self.key = key

        # Populate key schedule with split-up existing key
        self.key_schedule = []
        mask = 2 ** self.word_size - 1
        for i in range(self.key_words):
            self.key_schedule.append((self.key >> self.word_size * i) & mask)

        # Generate and add additional keys to round schedule using key_expansion function
        self.key_expansion()

    def split(self, plaintext):
        mask = (2 ** self.word_size) - 1
        try:
            x = (plaintext >> self.word_size) & mask
            y = plaintext & mask
            return x, y

        except TypeError:
            print("Invalid Plaintext! Please provide plaintext as Int type.")
            raise

    def left_circular_shift(self, num, bits):
        shift_mask = (2 ** self.word_size) - 1
        return ((num << bits) & shift_mask) | (num >> (self.word_size - bits))

    def right_circular_shift(self, num, bits):
        shift_mask = (2 ** self.word_size) - 1
        return (num >> bits) | (num << (self.word_size - bits) & shift_mask)

    def key_expansion(self):
        mask = (2 ** self.word_size) - 1
        for i in range(self.key_words, self.rounds):
            tmp = self.right_circular_shift(self.key_schedule[i - 1], 3)
            if (self.key_words == 4):
                tmp = tmp ^ self.key_schedule[i - 3]
            tmp = tmp ^ self.right_circular_shift(tmp, 1)
            self.key_schedule.append((~self.key_schedule[i - self.key_words] & mask) ^ tmp ^ self.z[self.j_value][
                (i - self.key_words) % 62] ^ 3)

    def encrypt(self, plaintext, fault=0):
        #if fault is defined =>  error injected in LT-5, else normal encryption occurs
        #returns ciphertext in binary (string)

        x, y = self.split(plaintext)

        for i in range(self.rounds):
            tmp = x
            x = y ^ (self.left_circular_shift(x, 1) & self.left_circular_shift(x, 8)) ^ self.left_circular_shift(x, 2) ^ \
                self.key_schedule[i]
            #at round T-5, a one-bit fault will be injected into the left half
            if (i == self.rounds - 6):
                x = x ^ fault
            y = tmp

        if(len(bin(x)[2:]) != self.word_size):
            x = "0b" + (self.word_size - len(bin(x)[2:]))*"0" + bin(x)[2:]
        else:
            x = bin(x)
        if (len(bin(y)[2:]) != self.word_size):
            y = (self.word_size - len(bin(y)[2:]))*"0" + bin(y)[2:]
        else:
            y = bin(y)[2:]

        cipherText_bin = x + y
        return cipherText_bin
