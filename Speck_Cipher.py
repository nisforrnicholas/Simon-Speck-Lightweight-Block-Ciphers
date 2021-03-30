"""
====================================================================================================================================
|  Basic Implementation of SPECK Lightweight Block Cipher for block sizes 32, 48, 64, 96 & 128 and their corresponding key sizes.  |
|  Author: Nicholas Leu, Date Created: 20/07/2020                                                                                  |
====================================================================================================================================

"""

class speckCipher:

    """
      PARAMETERS for SPECK cipher:
      format = block_size:{key_size:(rounds,key_words, a-value, b-value)}
      """
    parameters = {
        32: {64: (22, 4, 7, 2)},
        48: {72: (22, 3, 8, 3), 96: (23, 4, 8, 3)},
        64: {96: (26, 3, 8, 3), 128: (27, 4, 8, 3)},
        96: {96: (28, 2, 8, 3), 144: (29, 3, 8, 3)},
        128: {128: (32, 2, 8, 3), 192: (33, 3, 8, 3), 256: (34, 4, 8, 3)}
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

        # set up key_words
        self.key_words = self.possible_parameters[self.key_size][1]

        #set up alpha & beta rotation values
        self.a = self.possible_parameters[self.key_size][2]
        self.b = self.possible_parameters[self.key_size][3]

        # set up rounds
        self.rounds = self.possible_parameters[self.key_size][0]

        # set up key
        self.key = key

        # create Properly Sized bit mask
        self.mask = (2 ** self.word_size) - 1

        # Populate key schedule and l_schedule with split-up existing key
        self.key_schedule = []
        self.l_schedule = []
        self.key_schedule.append(self.key & self.mask)
        for i in range(1, self.key_words):
            self.l_schedule.append((self.key >> self.word_size * i) & self.mask)

        # Generate and add additional keys to round schedule using key_expansion function
        self.key_expansion()

    def left_circular_shift(self, num, bits):
        # shift_mask = (2 ** self.word_size) - 1
        return ((num << bits) & self.mask) | (num >> (self.word_size-bits))

    def right_circular_shift(self, num, bits):
        # shift_mask = (2 ** self.word_size) - 1
        return (num >> bits) | (num << (self.word_size-bits) & self.mask)

    def key_expansion(self):
        for i in range(self.rounds-1):
            self.l_schedule.append(((self.key_schedule[i] + self.right_circular_shift(self.l_schedule[i], self.a)) & self.mask) ^ i)
            self.key_schedule.append(self.left_circular_shift(self.key_schedule[i], self.b) ^ self.l_schedule[i+(self.key_words-1)])

    def split(self, plaintext):
        try:
            x = (plaintext >> self.word_size) & self.mask
            y = plaintext & self.mask
            return x, y

        except TypeError:
            print("Invalid Plaintext! Please provide plaintext as Int type.")
            raise

    def encrypt(self, plaintext):

        x,y = self.split(plaintext)

        for i in range(self.rounds):
            x = ((self.right_circular_shift(x, self.a) + y) & self.mask) ^ self.key_schedule[i]
            y = self.left_circular_shift(y, self.b) ^ x

        cipherText_str = hex(x) + hex(y)[2:]
        print("Encrypted Ciphertext: " + cipherText_str)
        cipherText_int = int(cipherText_str, 16)
        return cipherText_int

    def decrypt(self, ciphertext):

        x,y = self.split(ciphertext)

        self.key_schedule_rev = self.key_schedule[::-1]

        for i in range(self.rounds):
            tmp = ((x ^ self.key_schedule_rev[i]) - self.right_circular_shift(x^y, self.b)) & self.mask
            y = self.right_circular_shift((x ^ y), self.b)
            x = self.left_circular_shift(tmp, self.a)

        plaintext_str = hex(x) + hex(y)[2:]
        print("Decrypted Plaintext: " + plaintext_str)
        plaintext_int = int(plaintext_str, 16)
        return plaintext_int

