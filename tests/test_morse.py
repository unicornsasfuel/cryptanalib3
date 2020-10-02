import ca3

print('Testing Morse encode/decode...')

plaintext = b'I am the very model of an infosec professional'

morsed = ca3.morse_encode(plaintext)

assert ca3.morse_decode(morsed) == b'iamtheverymodelofaninfosecprofessional'
