from Simon_Cipher import simonCipher
from colorama import init,deinit,Fore,Style
init()

#SIMON32/64
print("Original plaintext: " + str(hex(0x65656877)))
simon = simonCipher(0x1918111009080100,32,64)
encrypted = simon.encrypt(0x65656877)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0xc69be9bb and decrypted == 0x65656877):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON48/72
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x6120676e696c)))
simon = simonCipher(0x1211100a0908020100,48,72)
encrypted = simon.encrypt(0x6120676e696c)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0xdae5ac292cac and decrypted == 0x6120676e696c):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON48/96
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x72696320646e)))
simon = simonCipher(0x1a19181211100a0908020100,48,96)
encrypted = simon.encrypt(0x72696320646e)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x6e06a5acf156 and decrypted == 0x72696320646e):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON64/96
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x6f7220676e696c63)))
simon = simonCipher(0x131211100b0a090803020100,64,96)
encrypted = simon.encrypt(0x6f7220676e696c63)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x5ca2e27f111a8fc8 and decrypted == 0x6f7220676e696c63):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON64/128
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x656b696c20646e75)))
simon = simonCipher(0x1b1a1918131211100b0a090803020100,64,128)
encrypted = simon.encrypt(0x656b696c20646e75)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x44c8fc20b9dfa07a and decrypted == 0x656b696c20646e75):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON96/96
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x2072616c6c69702065687420)))
simon = simonCipher(0x0d0c0b0a0908050403020100,96,96)
encrypted = simon.encrypt(0x2072616c6c69702065687420)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x602807a462b469063d8ff082 and decrypted == 0x2072616c6c69702065687420):
    print(simon.key_schedule)
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON96/144
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x74616874207473756420666f)))
simon = simonCipher(0x1514131211100d0c0b0a0908050403020100,96,144)
encrypted = simon.encrypt(0x74616874207473756420666f)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0xecad1c6c451e3f59c5db1ae9 and decrypted == 0x74616874207473756420666f):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON128/128
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x63736564207372656c6c657661727420)))
simon = simonCipher(0x0f0e0d0c0b0a09080706050403020100,128,128)
encrypted = simon.encrypt(0x63736564207372656c6c657661727420)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x49681b1e1e54fe3f65aa832af84e0bbc and decrypted == 0x63736564207372656c6c657661727420):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON128/192
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x206572656874206e6568772065626972)))
simon = simonCipher(0x17161514131211100f0e0d0c0b0a09080706050403020100,128,192)
encrypted = simon.encrypt(0x206572656874206e6568772065626972)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0xc4ac61effcdc0d4f6c9c8d6e2597b85b and decrypted == 0x206572656874206e6568772065626972):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON128/256
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x74206e69206d6f6f6d69732061207369)))
simon = simonCipher(0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100,128,256)
encrypted = simon.encrypt(0x74206e69206d6f6f6d69732061207369)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x8d2b5579afc8a3a03bf72a87efe7b868 and decrypted == 0x74206e69206d6f6f6d69732061207369):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

print(Style.RESET_ALL)
deinit()