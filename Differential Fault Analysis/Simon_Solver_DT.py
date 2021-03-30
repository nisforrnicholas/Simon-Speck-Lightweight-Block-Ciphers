from Simon_fault import simonfault

"""
========================================================================================================================
| Implementation of a basic Simon Block Cipher round key finder using DFA and differential trails.                     |
| Uses an efficient one-bit flip fault model, and constructed differential trail tables, at round T-5 to obtain the    |
| last 4 round keys first, before using the key schedule to find all other round keys.                                 |                                                                           |
| Run in conjunction with simonfault cipher class, which simulates fault injection at round T-5.                       |
| Works with all families of Simon.                                                                                    |
| Author: Nicholas Leu                                                                                                 |
========================================================================================================================

"""

def listify(input, word_size):
    """
    Converts binary string to list of bits
    :param input: binary string of length n, eg: "0b00...01"
    :param word_size: n, according to SIMON parameters set
    :return: integer list of bits
    """
    list = []
    input = input[2:]
    for i in range(word_size):
        list.append(int(input[i]))
    return list

def list_to_int(list):
    """
    Converts list of bits into its corresponding int
    :param list: list of bits
    :return: integer
    """
    tmp = ""
    for i in list:
        tmp = tmp + str(i)
    tmp = "0b" + tmp
    return int(tmp,2)

def generate_faults(word_size):
    """
    returns list of one-bit flipped int from original plaintext to represent faults
    :param word_size: n, according to SIMON parameters set
    :return: list of n integers
    """
    list = []
    base = word_size*"0"
    for i in range(word_size):
        tmp = "0b"+base[:i]+"1"+base[i+1:]
        list.append(int(tmp,2))
    return list

def find_DF_val(x_lst, df_lstc, df_lstf, pos, word_size):
    """
    :param x_lst: left half of the specific round
    :param df_lstc: df table value of specific round
    :param df_lstf: df table value of following round
    :param pos: bit position
    :param word_size: n
    :return: df table value of preceding round
    """
    dfp = (x_lst[(pos+1)%word_size]&df_lstc[(pos+8)%word_size]) ^ \
          (x_lst[(pos+8)%word_size]&df_lstc[(pos+1)%word_size]) ^ \
          (df_lstc[(pos+1)%word_size]&df_lstc[(pos+8)%word_size]) ^ \
          df_lstc[(pos+2)%word_size] ^ df_lstf[pos]
    return dfp

def find_keybits(xp, xf, yf, pos, word_size):
    """
    :param xp: X value of preceding round
    :param xf: X value of following round
    :param yf: Y value of following round
    :return: round key bits of specific round
    """
    return xp[pos] ^ formula(yf,pos,word_size) ^ xf[pos]

def formula(x, pos, word_size):
    return (x[(pos+1)%word_size] & x[(pos+8)%word_size]) ^ x[(pos+2)%word_size]

def right_circular_shift(num, bits, word_size):
    shift_mask = (2 ** word_size) - 1
    return (num >> bits) | (num << (word_size - bits) & shift_mask)

#Initialize Simon cipher
simon = simonfault(0x1918111009080100,32,64)
plaintext = 0x11111111
word_size = simon.word_size
block_size = simon.block_size

pattern_mod = {32:0, 48:8, 64:16, 96:32, 128:48}

#generate correct ciphertext (type:string) -> split into halves and convert to bit lists
ct_nf = simon.encrypt(plaintext)
XT = listify("0b"+ct_nf[2:word_size+2],word_size)
YT = listify("0b"+ct_nf[word_size+2:],word_size)

#generate list of faults
f_lst = generate_faults(word_size)

#DFT lists: Eg. DFT1 = DF table for round T-1
DFT = []; DFT1 = []; DFT2 = []; DFT3 = []; DFT4 = []
#X values: Eg. XT2 = X value of round T-2
XT2 = []; XT3 = []; XT4 = []; XT5 = []

for no in range(word_size):
    DFT.append([]); DFT1.append([]); DFT2.append([]); DFT3.append([]); DFT4.append([]);
    XT2.append(None); XT3.append(None); XT4.append(None); XT5.append(None)

for i in range(word_size):
    ct_f = simon.encrypt(plaintext, f_lst[i])
    XTF = listify("0b"+ct_f[2:word_size+2],word_size)
    YTF = listify("0b"+ct_f[word_size+2:],word_size)

    #obtain DFT and DFT1
    for j in range(word_size):
        DFT[i].append(XT[j] ^ XTF[j])
        DFT1[i].append(YT[j] ^ YTF[j])

    #obtain DFT2
    for k in range(word_size):
        DFT2[i].append(find_DF_val(YT, DFT1[i], DFT[i], k, word_size))
    #find respective XT-2 bits
    XT2[(i+3+pattern_mod[block_size])%word_size] = DFT1[i][(i+2+pattern_mod[block_size])%word_size] ^ DFT2[i][(i+4+pattern_mod[block_size])%word_size]
    XT2[(i+1)%word_size] = DFT1[i][(i+9+pattern_mod[block_size])%word_size] ^ DFT2[i][(i+11+pattern_mod[block_size])%word_size]

for i in range(word_size):
    # obtain DFT3
    for j in range(word_size):
        DFT3[i].append(find_DF_val(XT2, DFT2[i], DFT1[i], j, word_size))
    #obtain respective XT-3 bits
    XT3[(i+5+pattern_mod[block_size])%word_size] = DFT2[i][(i+4+pattern_mod[block_size])%word_size] ^ DFT3[i][(i+6+pattern_mod[block_size])%word_size]
    XT3[(i+3)%word_size] = DFT2[i][(i+11+pattern_mod[block_size])%word_size] ^ DFT3[i][(i+13+pattern_mod[block_size])%word_size]

for i in range(word_size):
    #obtain DFT4
    for j in range(word_size):
        DFT4[i].append(find_DF_val(XT3, DFT3[i], DFT2[i], j, word_size))
    #obtain respective XT-4 bits
    XT4[(i+7+pattern_mod[block_size])%word_size] = DFT3[i][(i+6+pattern_mod[block_size])%word_size] ^ DFT4[i][(i+8+pattern_mod[block_size])%word_size]
    XT4[(i+5)%word_size] = DFT3[i][(i+13+pattern_mod[block_size])%word_size] ^ DFT4[i][(i+15+pattern_mod[block_size])%word_size]

for i in range(word_size):
    # obtain respective XT-5 bits
    XT5[(i+9+pattern_mod[block_size])%word_size] = DFT4[i][(i+8+pattern_mod[block_size])%word_size]
    XT5[(i+7)%word_size] = DFT4[i][(i+15+pattern_mod[block_size])%word_size]

#obtain last 4 round keys
keyT1 = []; keyT2 = []; keyT3 = []; keyT4 = []
for i in range(word_size):
    keyT1.append(find_keybits(XT2, XT, YT, i, word_size))
    keyT2.append(find_keybits(XT3, YT, XT2, i, word_size))
    keyT3.append(find_keybits(XT4, XT2, XT3, i, word_size))
    keyT4.append(find_keybits(XT5, XT3, XT4, i, word_size))

#prepare key schedule list
key_schedule = []
for i in range(simon.rounds):
    key_schedule.append(None)
key_schedule[simon.rounds - 1] = list_to_int(keyT1); key_schedule[simon.rounds - 2] = list_to_int(keyT2)
key_schedule[simon.rounds - 3] = list_to_int(keyT3); key_schedule[simon.rounds - 4] = list_to_int(keyT4)

#solve for remaining round keys using key expansion
mask = (2 ** simon.word_size) - 1

for i in range(simon.rounds-1, simon.key_words-1, -1):
    tmp = right_circular_shift(key_schedule[i-1],3,word_size)
    if(simon.key_words == 4):
        tmp = tmp ^ key_schedule[i-3]
    tmp = tmp ^ right_circular_shift(tmp,1,word_size)
    result = key_schedule[i] ^ tmp ^ simon.z[simon.j_value][(i - simon.key_words) % 62] ^ 3
    key_schedule[i-simon.key_words] = ~result & mask

print("***\nThe full round key schedule is: ")
print(key_schedule)

master_key = ""
for i in range(simon.key_words-1,-1,-1):
    tmp = hex(key_schedule[i])[2:]
    total = int(simon.key_size / 4 / simon.key_words)
    if(len(tmp) != total):
        tmp = (total - len(tmp))*"0" + tmp
    master_key = master_key + tmp
master_key = "0x" + master_key

print("Master Key: " + master_key)
print("***")


