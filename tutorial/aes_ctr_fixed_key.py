from Crypto.Cipher import AES
import ca3
import sys
from binascii import hexlify

key = b'1234567890123456'
nonce = b'12345678'
flag = b'Reusing nonces with a stream cipher is bad!'

def encrypt(plaintext):
   return AES.new(key=key, mode=AES.MODE_CTR, nonce=nonce).encrypt(plaintext)

if len(sys.argv) != 2:
   print(f"The flag is {ca3.bytes2str(hexlify(encrypt(flag)))}")
   exit(f"Usage: {sys.argv[0]} <data_to_encrypt>")

print(ca3.bytes2str(hexlify(encrypt(ca3.str2bytes(sys.argv[1])))))
