import ca3

password = b'feather'
ciphertext = b'311334141512511221543441241233411113344124122135341331412125123512211333'

print('Testing Polybius...')

answer = ca3.polybius_decrypt(ca3.make_polybius_square(password),ciphertext)

assert(answer == b'iamtheverymodelofamodernmaiorgeneral')
