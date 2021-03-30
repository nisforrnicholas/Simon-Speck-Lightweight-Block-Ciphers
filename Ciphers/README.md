# Simon-Speck-Lightweight-Block-Ciphers
Both the implementations of Simon and Speck Lightweight Block Ciphers are to be utilized as imported classes. They both have encrypting and decrypting functionalities, and support the full range of block sizes: 32, 48, 64, 96 and 128 bits, and their corresponding key sizes.

**Example Usage**:

```python
from Simon_Cipher import simonCipher

# Initialize Simon Cipher (key, block_size, key_size)
simon = simonCipher(0x1918111009080100,32,64)

# Encrypt (Input Hex value)
encrypted = simon.encrypt(0x65656877)

# Decrypt
decrypted = simon.decrypt(encrypted)
```



The 'Simon_test' and 'Speck_test' Python files can be used to verify that the implemented ciphers are working as expected.