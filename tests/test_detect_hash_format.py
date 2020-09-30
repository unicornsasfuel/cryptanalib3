import ca3 as ca
from Crypto.Hash import MD5

plaintext = b'foo:bar'

words = [b'bar',b'baz',b'foo',b'garply']

hashes = [b'4e99e8c12de7e01535248d2bac85e732']

print('Testing hash format detection...')
result = ca.detect_hash_format(words,hashes)
if result != (b'foo:bar', 'md5'):
   raise Exception('Hash format detection is broken')
