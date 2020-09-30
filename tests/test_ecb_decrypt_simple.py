from Crypto.Cipher import AES
import ca3 as ca
from Crypto import Random
import random

key = b'YELLOW SUBMARINE'
iv = Random.new().read(AES.block_size)
prefix = b'A'*random.randint(1,4)
# suffix = sys.argv[1]
suffix = b'lol, u tk him 2 da bar|?duh'

cipher = AES.new(key, AES.MODE_ECB)

def my_encryption_oracle(plaintext):
   return cipher.encrypt(ca.pkcs7_pad(prefix + plaintext + suffix, AES.block_size))

print('Testing ECB secret suffix decryption (simple)')
decrypted_suffix = ca.ecb_cpa_decrypt(my_encryption_oracle, AES.block_size, verbose=True, hollywood=True)

if decrypted_suffix[:27] != suffix:
   raise Exception('ECB CPA secret suffix with fixed prefix decryption failed.')
