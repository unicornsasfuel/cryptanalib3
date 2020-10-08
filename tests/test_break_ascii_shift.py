import ca3

def do_ascii_shift(data,shift):
   result = b''
   for byte in data:
      result += bytes([(byte+shift) % 256])
   return result

plaintext = b'I am the very model of an infosec professional'

ciphertext = do_ascii_shift(plaintext, 49)

broken = ca3.break_ascii_shift(ciphertext)[0]

assert(broken == plaintext)
