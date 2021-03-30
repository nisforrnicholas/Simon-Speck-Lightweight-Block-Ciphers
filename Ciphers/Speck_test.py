from Speck_Cipher import speckCipher
from colorama import init,deinit,Fore,Style
init()

#SPECK32/64
print("Original plaintext: " + str(hex(0x6574694c)))
speck = speckCipher(0x1918111009080100,32,64)
encrypted = speck.encrypt(0x6574694c)
decrypted = speck.decrypt(encrypted)
if (encrypted == 0xa86842f2 and decrypted == 0x6574694c):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SPECK48/72
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x20796c6c6172)))
speck = speckCipher(0x1211100a0908020100,48,72)
encrypted = speck.encrypt(0x20796c6c6172)
decrypted = speck.decrypt(encrypted)
if (encrypted == 0xc049a5385adc and decrypted == 0x20796c6c6172):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SPECK48/96
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x6d2073696874)))
speck = speckCipher(0x1a19181211100a0908020100,48,96)
encrypted = speck.encrypt(0x6d2073696874)
decrypted = speck.decrypt(encrypted)
if (encrypted == 0x735e10b6445d and decrypted == 0x6d2073696874):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SPECK64/96
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x74614620736e6165)))
speck = speckCipher(0x131211100b0a090803020100,64,96)
encrypted = speck.encrypt(0x74614620736e6165)
decrypted = speck.decrypt(encrypted)
if (encrypted == 0x9f7952ec4175946c and decrypted == 0x74614620736e6165):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SPECK64/128
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x3b7265747475432d)))
speck = speckCipher(0x1b1a1918131211100b0a090803020100,64,128)
encrypted = speck.encrypt(0x3b7265747475432d)
decrypted = speck.decrypt(encrypted)
if (encrypted == 0x8c6fa548454e028b and decrypted == 0x3b7265747475432d):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SPECK96/96
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x65776f68202c656761737520)))
speck = speckCipher(0x0d0c0b0a0908050403020100,96,96)
encrypted = speck.encrypt(0x65776f68202c656761737520)
decrypted = speck.decrypt(encrypted)
if (encrypted == 0x9e4d09ab717862bdde8f79aa and decrypted == 0x65776f68202c656761737520):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SPECK96/144
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x656d6974206e69202c726576)))
speck = speckCipher(0x1514131211100d0c0b0a0908050403020100,96,144)
encrypted = speck.encrypt(0x656d6974206e69202c726576)
decrypted = speck.decrypt(encrypted)
if (encrypted == 0x2bf31072228a7ae440252ee6 and decrypted == 0x656d6974206e69202c726576):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SPECK128/128
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x6c617669757165207469206564616d20)))
speck = speckCipher(0x0f0e0d0c0b0a09080706050403020100,128,128)
encrypted = speck.encrypt(0x6c617669757165207469206564616d20)
decrypted = speck.decrypt(encrypted)
if (encrypted == 0xa65d9851797832657860fedf5c570d18 and decrypted == 0x6c617669757165207469206564616d20):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SPECK128/192
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x726148206665696843206f7420746e65)))
speck = speckCipher(0x17161514131211100f0e0d0c0b0a09080706050403020100,128,192)
encrypted = speck.encrypt(0x726148206665696843206f7420746e65)
decrypted = speck.decrypt(encrypted)
if (encrypted == 0x1be4cf3a13135566f9bc185de03c1886 and decrypted == 0x726148206665696843206f7420746e65):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SPECK128/256
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x65736f6874206e49202e72656e6f6f70)))
speck = speckCipher(0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100,128,256)
encrypted = speck.encrypt(0x65736f6874206e49202e72656e6f6f70)
decrypted = speck.decrypt(encrypted)
if (encrypted == 0x4109010405c0f53e4eeeb48d9c188f43 and decrypted == 0x65736f6874206e49202e72656e6f6f70):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

print(Style.RESET_ALL)
deinit()