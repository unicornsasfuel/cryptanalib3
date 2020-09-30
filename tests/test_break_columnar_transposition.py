import ca3 as ca

plaintext = b'I am the very model of a modern major-general, I\'ve information vegetable, animal and mineral, I know the kings of England and I quote the fights historical from Marathon to Waterloo in order categorical.'

num_rows = 6

ciphertext = b''.join([plaintext[num::num_rows] for num in range(num_rows)])

print('Testing columnar transposition solver...')

myplaintext = ca.break_columnar_transposition(ciphertext)
if myplaintext[0][0] != plaintext:
   raise Exception('Columnar transposition solver is broken.')
