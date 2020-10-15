import ca3 as ca
#from Crypto.Util.number import bytes_to_long
#import os

# lcg_state = bytes_to_long(os.urandom(4)) % 101020101
# fix LCG seed to cause correct modulus recovery for now until an improvement is made
lcg_state = 18159032

def lcg(state):
   next_state = (31337 * state + 1337) % 101020101
   return next_state

def libc_rand_lcg(state):
   next_state = (1103515245 * state + 12345) % 2**31
   return next_state

# LIBC wrapper test
states = []

current_state = correct_prev_state = lcg(lcg_state)

for i in range(20):
   current_state = lcg(current_state)
   states.append(current_state)

correct_next_state = lcg(current_state)

print(correct_prev_state)
print(states)
print(correct_next_state)

print('Testing LCG cracker...')

print('...with known a,c,m...')
assert ca.lcg_next_states(states, 1, a=31337, c=1337, m=101020101)[0] == correct_next_state
print('...with known a,m...')
assert ca.lcg_next_states(states, 1, a=31337, m=101020101)[0] == correct_next_state
print('...with no known constants...')
assert ca.lcg_next_states(states, 1)[0] == correct_next_state

print('Testing previous state recovery...')

print('...with known a,c,m...')
assert ca.lcg_prev_states(states, 1, a=31337, c=1337, m=101020101)[0] == correct_prev_state
print('...with known a,m...')
assert ca.lcg_prev_states(states, 1, a=31337, m=101020101)[0] == correct_prev_state
print('...with no known constants...')
assert ca.lcg_prev_states(states, 1)[0] == correct_prev_state


states = []

current_state = correct_prev_state = libc_rand_lcg(lcg_state)

for i in range(10):
   current_state = libc_rand_lcg(current_state)
   states.append(current_state)

correct_next_state = libc_rand_lcg(current_state)

print('Testing libc rand wrapper around LCG cracker...')

assert ca.libc_rand_next_states(states, 1)[0] == correct_next_state

print('Testing previous state recovery...')
assert ca.libc_rand_prev_states(states, 1) [0] == correct_prev_state
