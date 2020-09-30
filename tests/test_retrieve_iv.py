import ca3 as ca
from Crypto.Cipher import AES
from Crypto import Random

from binascii import hexlify

key = iv = Random.new().read(AES.block_size)

cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
second_cipher_because_yolo = AES.new(key, mode=AES.MODE_CBC, IV=iv)

ciphertext = cipher.encrypt(ca.pkcs7_pad(b'Check out the mic while the DJ revolves it (ICE ICE BABY)',AES.block_size))

def decryption_oracle(ciphertext):
   return second_cipher_because_yolo.decrypt(ciphertext)

print('Key and IV are %s and %s' % (hexlify(key), hexlify(iv)))
retrieved_iv = ca.retrieve_iv(decryption_oracle, ciphertext, AES.block_size)
print('Ciphertext is %s' % hexlify(ciphertext))
plaintext = decryption_oracle(ciphertext)
print('Produced plaintext is %s' % hexlify(plaintext))
print('First block of produced plaintext is %s' % hexlify(plaintext[:AES.block_size]))
print('Second block of produced plaintext is %s' % hexlify(plaintext[AES.block_size:AES.block_size*2]))
print('Retrieved IV is %s' % hexlify(retrieved_iv))

if iv != retrieved_iv:
   raise Exception('Decryption oracle IV retrieval is broken')

