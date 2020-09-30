from Crypto.Cipher import AES
import ca3 as ca
from Crypto import Random
import random
import pdb

key = b'YELLOW SUBMARINE'
iv = Random.new().read(AES.block_size)
suffix = b'lol, u tk him 2 da bar|?duh'

cipher = AES.new(key, AES.MODE_ECB)

def my_encryption_oracle(plaintext):
   return cipher.encrypt(ca.pkcs7_pad(b'A'*random.randint(1,AES.block_size) + plaintext + suffix, AES.block_size))

print("Testing ECB secret suffix decryption (hard)")
decrypted_suffix = ca.ecb_cpa_decrypt(my_encryption_oracle, AES.block_size, verbose=True, hollywood=True)

if decrypted_suffix[:27] != suffix:
   raise Exception('ECB CPA secret suffix with random length prefix decryption failed.')
