from Crypto.Cipher import AES
from Crypto import Random
import ca3 as ca
from time import sleep

plaintext = b'I am the very model of a modern major-general'
plaintext = ca.pkcs7_pad(plaintext, AES.block_size)
print("Plaintext is " + str(plaintext))

key = b'YELLOW SUBMARINE' #<3 matasano crypto challenges
iv = Random.new().read(AES.block_size)

def my_padding_oracle(ciphertext):
   dat_cipher = AES.new(key,AES.MODE_CBC,iv)
   try:
      ca.pkcs7_padding_remove(dat_cipher.decrypt(ciphertext),AES.block_size)
      return True
   except:
      return False

cipher = AES.new(key,AES.MODE_CBC,iv)
ciphertext = cipher.encrypt(plaintext)

print('Running the attack with known IV:')
result = ca.padding_oracle_decrypt(my_padding_oracle, ciphertext, block_size=AES.block_size, verbose=True, iv=iv)
print(result)
if result != plaintext:
   raise Exception('Vaudenay\'s padding oracle attack with IV knowledge is broken.')
print('')
print('Running the attack without knowledge of the IV:')
result = ca.padding_oracle_decrypt(my_padding_oracle, ciphertext, block_size=AES.block_size, verbose=True)
print(result)
if result[AES.block_size:] != plaintext[AES.block_size:]:
   raise Exception('Vaudenay\'s padding oracle attack without IV knowledge is broken.')
