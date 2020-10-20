"""
Cryptanalib - A series of useful functions for cryptanalysis
by Daniel "unicornFurnace" Crowley

dependencies - PyCryptodome
"""
import operator
import itertools
import sys
import zlib
from functools import reduce
import decimal
from binascii import unhexlify
from base64 import b64decode

from Crypto.Util import number as Cnumber

# This is ugly as sin, but it cleans up the namespace
import Crypto.Hash.MD5, Crypto.Hash.MD4, Crypto.Hash.MD2
import Crypto.Hash.RIPEMD, Crypto.Hash.SHA1, Crypto.Hash.SHA224
import Crypto.Hash.SHA256, Crypto.Hash.SHA384, Crypto.Hash.SHA512

from . import frequency
from . import helpers


hollywood_mask = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '
# -----------------------------------------
# Real-world attack functions
#
# These functions are meant to be called directly to attack cryptosystems implemented
# with modern crypto, or at least cryptosystems likely to be found in the real world.
# -----------------------------------------

def lcg_recover_parameters(states, a=None, c=None, m=None):
   '''
    Given the observed output of a Linear Congruential Generator
    calculates the modulus, the mutiplier, and the addend.
    Modulus recovery relies on the property that, given a set of
    numbers
                {k_1 * m, k_2 * m, ..., k_n * m}
    the, with high probability, it is:
            GCD(k_1 * m, k_2 * m, ..., k_n * m) = m
    To generate such a set with at least 2 numbers, at least 5
    states are required.
    Once the modulus is known, the multiplier and the addend
    can be easily recovered. The first requires exactly 3
    states, the second exactly 2.

    Inputs:
    ``[int, ...]`` states - Observed states of the LCG.
    ``int`` a - Multiplier.
    ``int`` c - Addend.
    ``int`` m - Modulus.

    Returns:
    ``(int, int, int)`` The recovered LCG parameters, ``a, c, m``.
    ``False`` when the parameters cannot be recovered

    Raises:
    ``ValueError`` if:
      ``m`` is ``None`` and ``len(states)`` < 5
      ``a`` is ``None`` and ``len(states)`` < 3
      ``c`` is ``None`` and ``len(states)`` < 2
    '''
   # Start modulus recovery
   if m is None:
      if len(states) < 5:
         raise ValueError('Modulus recovery requires at least 5 states.')


      diffs = [
         q - p
         for p, q in zip(states, states[1:])
      ]

      zeroes = [
         d2 * d0 - d1 ** 2
         for d0, d1, d2 in zip(diffs, diffs[1:], diffs[2:])
      ]

      m = reduce(Cnumber.GCD, zeroes)

      if m < 2:
         print('[-] Modulus could not be recovered, retry with different states.')
         return False
      else:
         print('[+] Modulus recovered: ', m)

   # Start multiplier recovery
   if a == None:
      if len(states) < 3:
         raise ValueError('Multiplier recovery requires at least 3 states.')

      inv = Cnumber.inverse(states[1] - states[0], m)
      # ``Crypto.Util.number.inverse`` silently fails and returns 1
      # so it's better to double check the result.
      if inv * (states[1] - states[0]) % m != 1:
         print('[-] Recovered modulus was incorrect.')
         # TODO: Check for small factors to correct modulus
         return False

      a = (states[2] - states[1]) * inv % m

      print('[+] Multiplier recovered: ', a)

   # Start addend recovery
   if c == None:
      if len(states) < 2:
         raise ValueError('Addend recovery requires at least 2 states.')

      c = (states[1] - a * states[0]) % m

   # Run a final check, to ensure the recovered parameters
   # are correct. This is done by starting from ``states[0]``
   # and testing if all other states can be generated.
   try:
      for current_state, next_state in zip(states, states[1:]):
         assert next_state == (current_state * a + c) % m
   except AssertionError:
      print('[-] Could not recover LCG parameters.')
      return False

   return a, c, m


def lcg_next_states(states, num_states=5, a=None, c=None, m=None):
   """
      Given the current state of an LCG, return the next states
   in sequence.

   Inputs:
   ``[int, ...]`` states - Known, complete states in order from the LCG.
   ``int`` num_states - The number of future states to generate.
   ``int`` a - The multiplier for the LCG.
   ``int`` c - The addend for the LCG.
   ``int`` m - The modulus for the LCG.

   Outputs:
   ``[int, ...]``

   Raises:
    ``ValueError`` if:
      ``m`` is ``None`` and ``len(states)`` < 5
      ``a`` is ``None`` and ``len(states)`` < 3
      ``c`` is ``None`` and ``len(states)`` < 2
   """

   if not all([a, c, m]):
      parameters = lcg_recover_parameters(states, a, c, m)
      if parameters == False:
         return False
      else:
         (a, c, m) = parameters

   current_state = states[-1]
   next_states = []
   for i in range(num_states):
      current_state = (a * current_state + c) % m
      next_states.append(current_state)

   return next_states


def lcg_prev_states(states, num_states=5, a=None, c=None, m=None):
   """
   Given a state or set of sequential states of an LCG, return the previous states in sequence.

   Inputs:
   ``[int, ...]`` states - Known sequential states from the LCG.
   ``int`` num_states - The number of past states to generate.
   ``int`` a - The multiplier for the LCG.
   ``int`` c - The addend for the LCG.
   ``int`` m - The modulus for the LCG.

   Outputs:
   ``[int, ...]``

   Raises:
   ``ValueError`` if:
      ``m`` is ``None`` and ``len(states)`` < 5
      ``a`` is ``None`` and ``len(states)`` < 3
      ``c`` is ``None`` and ``len(states)`` < 2
   """

   if not all([a, c, m]):
      parameters = lcg_recover_parameters(states, a, c, m)
      if parameters == False:
         return False
      else:
         (a, c, m) = parameters

   current_state = states[0]
   prev_states = []
   for i in range(num_states):
      current_state = (((current_state - c) % m) * Cnumber.inverse(a, m)) % m
      prev_states.insert(0, current_state)

   return prev_states


def libc_rand_next_states(known_states_in_order, num_states):
   '''
   A wrapper around lcg_next_states with hardcoded a, c, and m parameters.

   Inputs:
   ``[int, ...]`` known_states_in_order - a set of known, complete, sequential states output from libc's ``rand``,
      in order
   ``int`` num_states - the number of states to generate following the last item in the provided states

   Returns:
   ``[int, ...]``
   '''
   return lcg_next_states(known_states_in_order, num_states, a=1103515245, c=12345, m=2 ** 31)


def libc_rand_prev_states(known_states_in_order, num_states):
   '''
   A wrapper around lcg_prev_states with hardcoded
   a, c, and m parameters corresponding to libc rand(),
   used in C and Perl

   Inputs:
   ``[int, ...]`` known_states_in_order - a set of known, complete, sequential states output from libc's ``rand``,
      in order
   ``int`` num_states - the number of states to generate preceeding the last item in the provided states

   Returns:
   ``[int, ...]``
   '''
   return lcg_prev_states(known_states_in_order, num_states, a=1103515245, c=12345, m=2 ** 31)


def rsa_crt_fault_attack(faulty_signature, message, modulus, e=0x10001, verbose=False):
   '''
   Given a faulty signature, a message (with padding, if any, applied),
   the modulus, and public exponent, one can derive the private key used
   to sign the message.

   Inputs:
   ``int`` faulty_signature - A signature generated incorrectly
   ``int`` message - The signed message, as a number, with padding applied
   ``int`` modulus - The public modulus
   ``int`` e - The public exponent [defaults to the common 0x10001]

   Returns:
   ``int`` The private exponent d, if found, or
   ``False``
   '''
   p = helpers.gcd(pow(faulty_signature, e, modulus) - message, modulus)

   if p == 1:
      if verbose:
         print('[*] Couldn\'t factor the private key.')
      return False
   else:
      q = modulus // p
      d = helpers.derive_d_from_pqe(p, q, e)
      print('[!] Factored private key.')
      return d


def recover_rsa_modulus_from_signatures(m1, s1, m2, s2, e=0x10001):
   """
   Calculates the modulus used to produce RSA signatures from
   two known message/signature pairs and the public exponent.

   Since the most common public exponent is 65537, we default
   to that.
   
   Parameters:
   ``bytes`` m1 - The first message
   ``bytes`` s1 -  The signature of the first message
      as a bytestring
   ``bytes`` m2 -  The second message
   ``bytes`` s2 -  The signature of the second message
   ``int`` e - The exponent to use

   Returns:
   ``int`` the modulus, or
   ``False`` upon failure
   """
   m1 = helpers.bytes_to_int(m1)
   s1 = helpers.bytes_to_int(s1)
   m2 = helpers.bytes_to_int(m2)
   s2 = helpers.bytes_to_int(s2)
   gcd_result = Cnumber.GCD(pow(s1, e) - m1, pow(s2, e) - m2)

   if gcd_result < s1 or gcd_result < s2:
      # The modulus can never be smaller than our signature.
      # If this happens, we have been fed bad data.
      return False

   else:
      return int(gcd_result)


def small_message_rsa_attack(ciphertext, modulus, exponent, minutes=5, verbose=False):
   """
   With unpadded RSA, a sufficiently small exponent/message in comparison
   to the size of the modulus may result in a situation where the message,
   after exponentiation, does not exceed the bounds of the modulus, reducing
   decryption to:
   
   plaintext = ciphertext ** (1/exponent)

   Alternatively, there may be some small value for x such that:

   plaintext = (ciphertext + x*modulus) ** (1/exponent)
   
   Inputs:
   ``int`` ciphertext - The RSA encrypted message
   ``int`` modulus - The N, or modulus, of the public key
   ``int`` exponent - The e, or public exponent, of the public key
   Optional inputs:
   ``int`` minutes - A number of minutes to run the attack until giving up
   ``bool`` verbose - Whether or not to print status information. Slow.
   """
   from time import time
   current_time = int(time())
   end_time = current_time + (minutes * 60)

   count = multiplier = 1

   if verbose:
      print("Starting small message RSA attack...")

   while True:
      candidate_plaintext = helpers.nroot(decimal.Decimal(ciphertext + multiplier * modulus), exponent)
      candidate_plaintext = int(candidate_plaintext)
      if pow(candidate_plaintext, exponent, modulus) == ciphertext:
         answer_bytelen = int(helpers.ceil(Cnumber.size(candidate_plaintext) / 8))
         return candidate_plaintext.to_bytes(answer_bytelen, 'big')

      if count % 10 == 0:
         if time() > end_time:
            if verbose: print('')
            return None
         else:
            if verbose:
               sys.stdout.write("\rCurrent iteration: %d" % count)
               sys.stdout.flush()
      count += 1
      multiplier += 1


def wiener(N, e, minutes=10, verbose=False):
   """
   Wiener's attack against weak RSA keys:
   https://en.wikipedia.org/wiki/Wiener%27s_attack

   Developed by Maxime Puys.

   Inputs:
   ``int`` N -  modulus of the RSA key to factor using Wiener's attack.
   ``int`` e - public exponent of the RSA key.
   ``float`` minutes - number of minutes to run the algorithm before giving up
   ``bool`` verbose - Periodically show how many iterations have been

   Returns:
   ``int`` one of the factors of the modulus, or
   ``1`` if the process takes too long or fails
   """
   from time import time
   current_time = int(time())
   end_time = current_time + int(minutes * 60)

   def contfrac(x, y):
      """
      Returns the continued fraction of x/y as a list.
      """

      a = x // y
      b = a * y
      ret = [a]
      while b != x:
         x, y = y, x - b
         a = x // y
         b = a * y
         ret += [a]

      return ret

   def continuants(frac):
      """
      Returns the continuants of the continued fraction frac.
      """

      prec = (frac[0], 1)
      cur = (frac[1] * frac[0] + 1, frac[1])

      ret = [prec, cur]
      for x in frac[2:]:
         cur, prec = (x * cur[0] + prec[0], x * cur[1] + prec[1]), cur
         ret += [cur]

      return ret

   def polRoot(a, b, c):
      """
      Return an integer root of polynom ax^2 + bx + c.
      """

      delta = abs(b * b - 4 * a * c)
      return (-b - decimal.Decimal.sqrt(delta)) / (2 * a)

   if verbose:
      print("Computing continued fraction.")

   decimal.getcontext().prec = 4096
   N = decimal.Decimal(N)
   frac = contfrac(e, N)

   if verbose:
      print("Computing continuants from fraction.")

   conv = continuants(frac)
   current_continuant = 1
   total_continuants = len(conv)

   for k, d in conv:
      if time() > end_time:
         if verbose:
            print("Time expired, returning 1.")
            return 1

      if k > 0:
         phi = (e * d - 1) // k
         if verbose:
            sys.stdout.write("\rTesting continuant %d of %d" % (current_continuant, total_continuants))
            current_continuant += 1

         root = polRoot(1, N - phi + 1, N)

         if root != 0:
            if N % root == 0:
               if verbose:
                  print("\nModulus factored!")
               return -root

   return 1


def fermat_factor(N, minutes=10, verbose=False):
   """
   Code based on Sage code from FactHacks, a joint work by
   Daniel J. Bernstein, Nadia Heninger, and Tanja Lange.

   http://facthacks.cr.yp.to/

   Inputs:
   ``int`` N - modulus to attempt to factor using Fermat's Last Theorem
   ``float`` minutes - number of minutes to run the algorithm before giving up
   ``bool`` verbose - Periodically show how many iterations have been
      attempted

   Returns:
   ``[int, int]`` p and q, the two private factors of N
   """
   from time import time
   current_time = int(time())
   end_time = current_time + int(minutes * 60)

   decimal.getcontext().prec = 4096
   N = decimal.Decimal(N)

   def is_square(n):
      sqrt_n = n.sqrt()
      return helpers.floor(sqrt_n) == sqrt_n

   if verbose:
      print("Starting factorization...")

   if N <= 0:        return [1, N]
   if N % 2 == 0:    return [2, N / 2]

   sqrt_n = N.sqrt()
   a = helpers.ceil(sqrt_n)
   count = 0

   while not is_square(a ** 2 - N):
      a += 1
      count += 1
      if verbose:
         if count % 1000000 == 0:
            sys.stdout.write("\rCurrent iterations: %d" % count)
            sys.stdout.flush()
      if time() > end_time:
         if verbose: print("\nTime expired, returning [1,N]")
         return [1, N]

   b = decimal.Decimal.sqrt(a ** 2 - N)
   print("\nModulus factored!")
   return [int(a - b), int(a + b)]


def bb98_padding_oracle(ciphertext, padding_oracle, exponent, modulus, verbose=False, debug=False):
   """
   Bleichenbacher's RSA-PKCS1-v1_5 padding oracle from CRYPTO '98
   
   Given an RSA-PKCS1-v1.5 padding oracle and a ciphertext,
   decrypt the ciphertext.

   Inputs:
   ``int`` ciphertext - The ciphertext to decrypt
   ``function`` padding_oracle - A function that communicates with the padding oracle.
      The function should take a single bytestring as the ciphertext, and
      should return either ``True`` for good padding or ``False`` for bad padding.
   ``int`` exponent - The public exponent of the keypair
   ``int`` modulus - The modulus of the keypair
   ``bool`` verbose - Whether to show verbose output
   ``bool`` debug - Show very verbose output

   Outputs:
   ``bytes`` the decrypted value, or
   ``False`` upon failure
   """

   decimal.getcontext().prec = len(str(modulus))
   # Preamble:
   modulus_bit_length = Cnumber.size(int(modulus))
   modulus_bit_length += (modulus_bit_length % 8)
   k = modulus_bit_length // 8
   B = 2 ** (8 * (k - 2))
   # constants to avoid recomputation
   B2 = 2 * B
   B3 = 3 * B

   def get_r_values(s, M):
      R = []
      for a, b in M:
         low_val = helpers.ceil((a * decimal.Decimal(s) - B3 + 1) / modulus)
         high_val = helpers.floor((b * decimal.Decimal(s) - B2) / modulus)
         R.extend([x for x in range(low_val, high_val + 1)])
      if verbose and len(R) > 1:
         print("Found %d possible r values, trying to narrow to one..." % len(R))
      return R

   def step2(search_number, i, M):
      if i == 1 or len(M) > 1:
         # Step 2a/2b
         while True:
            if debug:
               sys.stdout.write("\rCurrent search number: %d" % search_number)
               sys.stdout.flush()
            search_number += 1
            test_ciphertext = c0 * pow(search_number, exponent, modulus)
            test_ciphertext %= modulus
            if padding_oracle(Cnumber.long_to_bytes(test_ciphertext)):
               if verbose:
                  print("Found s1! Starting to narrow search interval...")
               return (search_number)
      else:
         # Step 2c
         a = list(M)[0][0]
         b = list(M)[0][1]
         r = helpers.ceil(2 * (b * decimal.Decimal(search_number) - B2) / modulus)
         while True:
            s_range_bottom = helpers.ceil((B2 + r * decimal.Decimal(modulus)) / b)
            s_range_top = helpers.floor((B3 - 1 + r * decimal.Decimal(modulus)) / a)
            s = s_range_bottom
            while s <= s_range_top:
               test_ciphertext = c0 * pow(s, exponent, modulus)
               test_ciphertext %= modulus
               if padding_oracle(Cnumber.long_to_bytes(test_ciphertext)):
                  return (s)
               s += 1
            r += 1

   def step3(s, M, R):
      new_M = set([])
      for a, b in M:
         for r in R:
            new_a = max(a, helpers.ceil((B2 + r * decimal.Decimal(modulus)) / s))
            new_b = min(b, helpers.floor((B3 - 1 + r * decimal.Decimal(modulus)) / s))
            if new_a <= new_b:
               new_M |= set([(new_a, new_b)])
      if len(new_M) == 0:
         return M
      else:
         return new_M

   # Step 1: Blinding
   # Initialize search number s, blinding number s0, and iteration count i
   s = s0 = i = 1
   ct_is_pkcs_conforming = padding_oracle(ciphertext)
   if verbose:
      if ct_is_pkcs_conforming:
         print("Original ciphertext corresponds to a PKCS1v1.5-conformant message. Skipping blinding...")
      else:
         print("Original ciphertext does not correspond to a PKCS1v.1.5-conformant message. Blinding...")

   c0 = Cnumber.bytes_to_long(ciphertext)
   M = set([(B2, B3 - 1)])
   # if the ciphertext provided corresponds to a PKCS1v1.5-conforming message, skip blinding
   while ct_is_pkcs_conforming == False:
      s += 1
      test_c0 = helpers.rsa_blind(c0, s, exponent, modulus)
      if padding_oracle(Cnumber.long_to_bytes(test_c0)):
         if verbose:
            print("Found s0 = %d, blinding complete. Searching for s1..." % s)
         ct_is_pkcs_conforming = True
         c0 = test_c0
         s0 = s

   while True:
      # Step 2: Searching for PKCS conforming messages
      s = step2(s, i, M)
      # Step 3: Narrowing the set of solutions
      R = get_r_values(s, M)
      M = step3(s, M, R)
      # Step 4: Computing the solution
      list_M = list(M)
      interval_bit_length = Cnumber.size(list_M[0][1] - list_M[0][0])
      if verbose and (len(M) == 1):
         sys.stdout.write("\rCurrent interval bit length: %d | Iterations finished: %d  " % (interval_bit_length, i))
         sys.stdout.flush()
      if len(M) == 1 and interval_bit_length < 8:
         for message in range(list_M[0][0], list_M[0][1] + 1):
            if debug:
               print('Debug: encrypted message is %r' % Cnumber.long_to_bytes(int(pow(decimal.Decimal(message), s0, modulus))))
            if int(pow(decimal.Decimal(message), exponent, modulus)) == c0:
               return Cnumber.long_to_bytes(helpers.rsa_unblind(message, s0, modulus))
         # Something went wrong...
         print("something went wrong.")
         return False
      i += 1


def xor_known_plaintext(matched_plaintext, matched_ciphertext, unmatched_ciphertext):
   """
   Given matching plaintext/ciphertext values, derive the key and decrypt another ciphertext encrypted
   under the same key.

   Inputs:
   ``bytes``  matched_plaintext - The plaintext half of a plaintext/ciphertext pair
   ``bytes`` matched_ciphertext - The ciphertext half of a plaintext/ciphertext pair
   ``bytes`` unmatched_ciphertext - A ciphertext whose plaintext is unknown

   Outputs:
   ``bytes``
   """
   return helpers.sxor(helpers.sxor(matched_plaintext, matched_ciphertext), unmatched_ciphertext)


def cbc_edit(old_plaintext, new_plaintext, old_ciphertext):
   '''
   Calculate the new ciphertext needed to make particular edits to plaintext
   through ciphertext modification.

   ``bytes`` old_plaintext - The old block of plaintext to be modified
   ``bytes`` new_plaintext - The new block of plaintext to be modified
   ``bytes`` old_ciphertext - The block of ciphertext to modify in order to make the
      changes. For CBC mode ciphertext, this is the previous block or IV.
      For stream ciphertext, this is the block of ciphertext corresponding
      to the old_plaintext.

   Outputs:
   ``bytes``
   '''
   if not (len(old_plaintext) == len(new_plaintext) == len(old_ciphertext)):
      raise InputLengthException

   edits = helpers.sxor(old_plaintext, new_plaintext)
   return helpers.sxor(old_ciphertext, edits)


def analyze_ciphertext(data, verbose=False, freq_table=frequency.frequency_tables['english']):
   """
   Takes in a list of samples and analyzes them to determine what type
   of samples they may be.

   Handles various data formats:
   zlib
   Base64
   ASCII hex
   URL
   OpenSSL salted data formatting

   Checks for:
   Randomness of the data (to identify output of a CSPRNG/RNG/strong cipher)
   Block cipher vs Stream cipher
   ECB mode
   CBC with fixed IV
   Hashes based on a Merkle-Damgard construction
   Stream cipher key reuse

   Inputs:
   ``[bytes, ...]`` data - A list of samples to analyze
   ``bool`` verbose - Display messages regarding analysis results

   Outputs:
   A dict with the following keys and value types:
   ``
   {                                    # Do the samples appear to be...
   "ecb": bool,                         # ...encrypted in EBC mode?
   "cbc_fixed_iv": bool,                # ...encrypted in CBC mode, with a fixed IV?
   "blocksize": int or False,           # ...encrypted with a block cipher? If so, the block size, else False.
   "md_hashes": bool,                   # ...(MD2, MD4, MD5) hashes?
   "sha1_hashes": bool,                 # ...SHA-1 hashes?
   "sha2_hashes": bool,                 # ...SHA-2 hashes?
   "individually_random": bool,         # ...high-entropy, when analyzed one at a time?
   "collectively_random": bool,         # ...high-entropy, when analyzed all together?
   "is_openssl_formatted": bool,        # ...generated with OpenSSL?
   "key_reuse": bool,                   # ...generated with the same stream cipher key?
   "rsa_key": bool,                     # ...RSA keys?
   "rsa_private_key": bool,             # ...RSA private keys?
   "rsa_small_n": bool,                 # ...RSA keys with a dangerously small key size?
   "is_transposition_only": bool,       # ...encrypted with a transposition cipher?
   "is_polybius": bool,                 # ...encrypted with the Polybius cipher?
   "is_all_alpha": bool,                # ...all alphabetic?
   "decoded_ciphertexts": [bytes, ...]  # The ciphertexts, after being decoded.
   }
   """
   data = [x for x in data if x != None and x != '']
   freq_table_only_lowercase = dict([x for x in freq_table.items() if x[0].islower()])
   results = {}
   result_properties = ['ecb', 'cbc_fixed_iv', 'blocksize', 'md_hashes',
                        'sha1_hashes', 'sha2_hashes', 'individually_random', 'collectively_random',
                        'is_openssl_formatted', 'decoded_ciphertexts', 'key_reuse', 'rsa_key', 'rsa_private_key',
                        'rsa_small_n']
   result_properties.extend(['is_transposition_only', 'is_polybius', 'is_all_alpha'])
   for result_item in result_properties:
      results[result_item] = False
   results['keywords'] = []
   data_properties = {}
   rsa_moduli = []
   num_messages = len(data)
   for datum, index in zip(data, range(num_messages)):
      # analyze each ciphertext to determine various individual properties
      data_properties[index] = {}
      data_properties[index]['is_openssl_formatted'] = (datum[:8] == "Salted__")
      data_properties[index]['base64_encoded'] = helpers.is_base64_encoded(datum)
      data_properties[index]['hex_encoded'] = helpers.is_hex_encoded(datum)
      data_properties[index]['zlib_compressed'] = helpers.is_zlib_compressed(datum)
      data_properties[index]['blocksize'] = helpers.detect_block_cipher(datum)

      # Check if sample is RSA key, if so, check properties
      (data_properties[index]['rsa_key'],
       data_properties[index]['rsa_private_key'],
       data_properties[index]['rsa_n_length']) = helpers.check_rsa_key(datum)

      # check for silly/classical crypto here
      data_properties[index]['is_transposition_only'] = (
                 helpers.detect_plaintext(datum.lower(), freq_table_only_lowercase, detect_words=False) < 1
      )
      data_properties[index]['is_polybius'] = helpers.detect_polybius(datum)
      data_properties[index]['is_all_alpha'] = all(
         [chr(char) in ' qwertyuiopasdfghjklzxcvbnm' for char in datum.lower()]
      )
   if all([data_properties[datum]['is_openssl_formatted'] for datum in data_properties]):
      if verbose:
         print('[+] Messages appear to be in OpenSSL format. Stripping OpenSSL header and analyzing again.')
      return analyze_ciphertext([x[16:] for x in data], verbose=verbose)
   if all([data_properties[datum]['hex_encoded'] for datum in data_properties]):
      if verbose:
         print('[+] Messages appear to be ASCII hex encoded, hex decoding and analyzing again.')
      return analyze_ciphertext([unhexlify(x) for x in data], verbose=verbose)
   if all([data_properties[datum]['zlib_compressed'] for datum in data_properties]):
      if verbose:
         print('[+] Messages appear to be zlib compressed, decompressing and analyzing again.')
      return analyze_ciphertext(list(map(zlib.decompress, data)), verbose=verbose)
   if all([data_properties[datum]['base64_encoded'] and not data_properties[datum]['is_all_alpha'] for datum in
           data_properties]):
      if verbose:
         print('[+] Messages appear to be Base64 encoded, Base64 decoding and analyzing again.')
      return analyze_ciphertext([b64decode(x) for x in data], verbose=verbose)
   min_blocksize = min([data_properties[datum]['blocksize'] for datum in data_properties])

   # perhaps we're dealing with hashes?
   if len(set([len(datum) for datum in data])) == 1:
      sample_length = list(set([len(datum) for datum in data]))[0]
      if sample_length == 16:
         results['md_hashes'] = True
         results['keywords'].append('md_hashes')
         if verbose:
            print('[+] Messages are all of length 16. This suggests MD5, MD4, or MD2 hashes.')
            print('[!] Consider attempting hash-length extension attacks.')
            print('[!] Consider attempting brute-force attacks.')
      elif sample_length == 20:
         results['sha1_hashes'] = True
         results['keywords'].append('sha1_hashes')
         if verbose:
            print('[+] Messages are all of length 20. This suggests RIPEMD-160 or SHA1 hashes.')
            print('[!] Consider attempting hash-length extension attacks.')
            print('[!] Consider attempting brute-force attacks.')
      elif sample_length in [28, 32, 48, 64]:
         results['sha2_hashes'] = True
         results['keywords'].append('sha2_hashes')
         if verbose:
            print('[+] Messages all have equal length matching one possible output length of SHA-2 hashes.')
            print('[!] Consider attempting hash-length extension attacks.')
            print('[!] Consider attempting brute-force attacks.')

   # Are we dealing with RSA keys?
   if all([data_properties[datum]['rsa_key'] for datum in data_properties]):
      if verbose:
         print('[+] At least one RSA key was discovered among the samples.')
      results['keywords'].append('rsa_key')
      # Any private keys?
      if any([data_properties[datum]['rsa_private_key'] for datum in data_properties]):
         if verbose:
            print('[!] At least one of the RSA keys discovered contains a private key component.')
      # Any critically small primes?
      if any([0 < data_properties[datum]['rsa_n_length'] <= 512 for datum in data_properties]):
         results['keywords'].append('rsa_small_n')
         if verbose:
            print(
               '[!] At least one of the RSA keys discovered has a bit length <= 512. This key can reasonably be factored with a single off-the-shelf computer.')
      # Any proven dangerously small primes?
      elif any([0 < data_properties[datum]['rsa_n_length'] < 768 for datum in data_properties]):
         results['keywords'].append('rsa_small_n')
         if verbose:
            print(
               '[!] At least one of the RSA keys discovered has a bit length <= 768. This key can be factored with a large number of computers such as a botnet, or large cluster.')
      # Any theoretical dangerously small primes?
      elif any([0 < data_properties[datum]['rsa_n_length'] < 1024 for datum in data_properties]):
         results['keywords'].append('rsa_small_n')
         if verbose:
            print(
               '[!] At least one of the RSA keys discovered has a bit length <= 1024. This key can be factored with a large number of computers such as a botnet, or large cluster.')
      if len(set(rsa_moduli)) < len(rsa_moduli):
         results['keywords'].append('rsa_n_reuse')
         if verbose:
            print(
               '[!] Two or more of the keys have the same modulus. Anyone who holds the private component for one of these keys can derive the private component for any of the others.')

   elif min_blocksize:
      results['keywords'].append('block')
      results['blocksize'] = min_blocksize
      if verbose:
         print('[+] Messages may be encrypted with a block cipher with block size ' + str(min_blocksize) + '.')
         print('[!] Consider attempting padding oracle attacks.')
         if min_blocksize == 32:
            print('[+] A block size of 32 is rare. The real block size is more likely 16 or 8.')
      for datum in data:
         if helpers.detect_ecb(datum)[0]:
            results['ecb'] = True
            results['keywords'].append('ecb')
      if (results['ecb'] == True) and verbose:
         print('[!] ECB mode detected. ECB mode has known vulnerabilities.')
         print('[!] Consider attempting block shuffling attacks.')
         print('[!] Consider attempting bytewise ECB decryption.')
      if not results['ecb']:
         if helpers.detect_ecb(b''.join(data))[0]:
            results['cbc_fixed_iv'] = True
            results['keywords'].append('cbc_fixed_iv')
            if verbose:
               print(
                  '[!] Duplicate blocks detected between messages. This indicates either ECB mode or CBC mode with a fixed IV.')
               print('[!] Consider attempting bytewise CBC-fixed-IV decryption.')


   # we don't appear to be working with a block cipher, so maybe stream cipher or homebrew
   else:
      if verbose:
         print('[+] Messages may be encrypted with a stream cipher or simple XOR.')
      if len(data) > 1:
         results['key_reuse'] = key_reused = helpers.check_key_reuse(data)
      else:
         results['key_reuse'] = key_reused = None
      if key_reused:
         results['keywords'].append('key_reuse')
      results['individually_random'] = individually_random = all([helpers.is_random(datum) for datum in data])
      if not individually_random:
         results['keywords'].append('individually_low_entropy')
      results['collectively_random'] = collectively_random = helpers.is_random(b''.join(data))
      if not collectively_random:
         results['keywords'].append('collectively_low_entropy')
      if verbose:
         if individually_random:
            if collectively_random:
               if key_reused:
                  print('[!] Messages have passed randomness tests, but show signs of key reuse.')
                  print('[!] Consider using the break_many_time_pad attack, or attempting crib dragging.')

               else:
                  print('[+] Messages have passed statistical randomness tests individually and collectively.')
                  print('[+] This suggests strong crypto.')

            else:
               print('[!] Messages have passed statistical randomness tests individually, but NOT collectively.')
               print('[!] This suggests key reuse.')
               print('[!] Consider using the break_many_time_pad attack, or attempting crib dragging.')

         else:
            print('[!] Individual messages have failed statistical tests for randomness.')
            print('[!] This suggests weak crypto is in use.')
            print('[!] Consider running single-byte or multi-byte XOR solvers.')

   # checks for silly classical crypto
   if all([data_properties[datum]['is_transposition_only'] for datum in data_properties]) and not 'rsa_key' in results[
      'keywords']:
      results['is_transposition_only'] = True
      results['keywords'].append('transposition')
      if verbose:
         print('[!] Ciphertexts match the frequency distribution of a transposition-only ciphertext.')
         print('[!] Consider using transposition solvers (rail fence, columnar transposition, etc)')
   if all([data_properties[datum]['is_polybius'] for datum in data_properties]):
      results['is_polybius'] = True
      results['keywords'].append('polybius')
      if verbose:
         print('[!] Ciphertexts appear to be a grid cipher (like polybius).')
         print('[!] Consider running simple substitution solvers.')
   if all([data_properties[datum]['is_all_alpha'] for datum in data_properties]):
      results['is_all_alpha'] = True
      results['keywords'].append('alpha')
      if verbose:
         print('[!] Ciphertexts are all alphabet characters.')
         print('[!] Consider running an alphabetical shift solver.')
   results['decoded_ciphertexts'] = data
   return results


def ecb_cpa_decrypt(encryption_oracle, block_size, verbose=False, hollywood=True,
                    charset=frequency.optimized_charset['english']):
   """
   In the case that you have access to a system that will encrypt data of your choice, with secret data appended to it,
   with any block cipher in ECB mode, and return the encrypted data to you, it is possible to recover the secret
   data with a series of queries.
   
   Parameters:
   ``function`` encryption_oracle - A function that will encrypt arbitrary data in ECB mode with
      a fixed secret suffix to be decrypted. It must accept a single ``bytes`` input, and return the raw
      result as ``bytes``.
   ``int`` blocksize - The block size of the cipher in use (usually 8 or 16)

   Optional parameters:
   ``bool`` verbose - Provide verbose output
   ``bool`` hollywood - Silly hollywood-style visualization
   ``bytes`` charset - A string of characters that could possibly be in the decrypted data, where the first
      character is the most common and the last is the least common. This should include at the very least all
      the possible padding characters. For instance, with PKCS#7 style padding, \\x01 through \\x10 should be
      included in the character set.

   Returns:
   The secret data.
   """

   # ------------------------------
   # Helper functions for ECB CPA bytewise decryption
   #
   def find_egg(ciphertext, block_size):
      ciphertext_blocks = helpers.split_into_blocks(ciphertext, block_size)
      num_blocks = len(ciphertext_blocks)
      if num_blocks < 4:
         return None
      for offset in range(num_blocks - 4):
         if (ciphertext_blocks[offset] == ciphertext_blocks[offset + 1]) and (
                 ciphertext_blocks[offset + 2] == ciphertext_blocks[offset + 3]):
            return ((offset * block_size) + (4 * block_size))
      return None

   def try_forever_egghunt_encryption_oracle(encryption_oracle, block_size, plaintext):
      while True:
         ciphertext = encryption_oracle(plaintext)
         egg_offset = find_egg(ciphertext, block_size)
         if egg_offset != None:
            return ciphertext[egg_offset:]

   #
   # -------------------------------

   # -------------------------------
   # Variable setup
   #
   bytes_to_boundary = 0
   # helps us find where our plaintext lies in the ciphertext
   egg = b'A' * (block_size * 2) + b'B' * (block_size * 2)
   # encrypt data of different lengths until egg is found
   bytes_to_boundary = None
   for tries in range(20):
      for length in range(block_size):
         if find_egg(encryption_oracle((b'A' * length) + egg), block_size) != None:
            bytes_to_boundary = length
            break
      if bytes_to_boundary != None:
         break
   if bytes_to_boundary == None:
      # For whatever reason, we couldn't get a length after 20 tries
      return False
   # get to the byte boundary so we're aligned to boundaries
   padding = b'A' * bytes_to_boundary
   prev_plaintext_block = b'A' * block_size
   ciphertext_to_decrypt = try_forever_egghunt_encryption_oracle(encryption_oracle, block_size, padding + egg)
   plaintext = b''
   decryption_complete = False

   if verbose:
      num_blocks = len(ciphertext_to_decrypt) / block_size
      num_current_block = 0
   #
   # -------------------

   # iterate through each block of ciphertext to decrypt
   for offset in range(0, len(ciphertext_to_decrypt), block_size):
      if verbose:
         num_current_block += 1
         print("[+] Decrypting block %d of %d" % (num_current_block, num_blocks))
      decrypted_bytes = b''
      # iterate through each byte of each ciphertext block
      for current_byte in range(1, block_size + 1):
         working_block = prev_plaintext_block[current_byte:]
         # Use the oracle to determine what our working block should look like
         # when we have the correct byte
         correct_byte_block = try_forever_egghunt_encryption_oracle(encryption_oracle, block_size,
                                                                    padding + egg + working_block)[
                              offset:offset + block_size]
         working_block += decrypted_bytes
         # Try each byte until we match the block indicating the correct byte
         for char in charset:
            if verbose and hollywood:
               # Silly hollywood style visualization of decryption process
               current_progress = helpers.output_mask(decrypted_bytes, hollywood_mask)
               chaff = helpers.output_mask(bytes([char]) * (block_size - current_byte), hollywood_mask)
               sys.stdout.write(f"\r {helpers.bytes2str(current_progress+chaff)}")
               sys.stdout.flush()
            if try_forever_egghunt_encryption_oracle(encryption_oracle, block_size,
                                                     padding + egg + working_block + bytes([char]))[
               :block_size] == correct_byte_block:
               decrypted_bytes += bytes([char])
               break
            if bytes([char]) == charset[-1]:
               # We seem to have reached the padding now
               decryption_complete = True
      # set our working block to be the block we've just decrypted so we can
      # correctly compare our "correct_byte_block" to our working block
      prev_plaintext_block = decrypted_bytes
      plaintext += decrypted_bytes
      if verbose:
         print("\n[+] Decrypted block: %s" % decrypted_bytes)
   return plaintext


'''
TODO: Extend the attack to other forms of padding that
can be used with Vaudenay's technique
'''


def padding_oracle_decrypt(padding_oracle, ciphertext, block_size, padding_type='pkcs7', iv=None, prefix=b'',
                           verbose=False, hollywood=True, charset=frequency.optimized_charset['english']):
   """
   Given a padding oracle function that accepts raw ciphertext and returns
   True for good padding or False for bad padding, and a ciphertext to decrypt:
   Perform Vaudenay's PO -> DO attack
   
   Parameters:
   ``function`` padding_oracle - A function that takes a ciphertext as its only parameter
      and returns ``True`` for good padding or ``False`` for bad padding
   ``bytes`` ciphertext - The ciphertext to be decrypted
   ``int`` block_size - The block size of the cipher in use

   Optional parameters:
   ``string`` padding_type - Type of padding in use. Currently only pkcs7 is supported.
   ``bytes`` iv - IV for decryption of first block, if known. Must be one block in length.
   ``bytes`` prefix - Ciphertext to place before any ciphertext being sent to the oracle.
   ``bool`` verbose - Provide direct output and progress indicator
   ``bool`` hollywood - Do hollywood style progress indication. Requires verbose.
   ``bytes`` charset - A string of characters that could possibly be in the decrypted data,
      where the first character is the most common and the last is the least common. This should include
      at the very least all the possible padding characters. For instance, with PKCS#7 style padding,
      \\x01 through \\x10 should be included in the character set.

   Returns:
   ``bytes`` The data, decrypted.
   """
   plaintext = intermediate_block = b''
   ciphertext_blocks = helpers.split_into_blocks(ciphertext, block_size)
   # --------------
   # Check our parameters to make sure everything has been put in correctly
   #
   if len(prefix) % block_size != 0:
      print('[!] Error: Bad prefix for padding_oracle_decrypt()')
      return False
   if len(ciphertext) % block_size != 0:
      print('[!] Error: Bad ciphertext length for padding_oracle_decrypt()')
      return False
   if iv != None:
      if len(iv) != block_size:
         print('[!] Error: Bad IV length for padding_oracle_decrypt()')
         return False
      # we set the previous block as the IV so that the first block decrypts correctly
      prev_block = iv
   else:
      # If we haven't received an IV, try a block of nulls as this is commonly
      # used as an IV in practice.
      if verbose:
         print(
            '[*] No IV was provided, using a block of null bytes instead. Unless a block of null bytes is being'\
            'used as the IV, expect the first block to be garbled.'
         )
      prev_block = b"\x00" * block_size
   #
   # --------------

   num_blocks = len(ciphertext_blocks)
   num_current_block = 1
   if verbose:
      print("")
   # iterate through each block of ciphertext
   for block_to_decrypt in ciphertext_blocks:
      if verbose:
         sys.stdout.write("\rDecrypting block %d of %d" % (num_current_block, num_blocks))
         sys.stdout.flush()
         if hollywood:
            print("")
         num_current_block += 1
      # convert the ciphertext to a list to allow for direct substitutions
      temp_ciphertext = list(prefix + (b"\x00" * block_size) + block_to_decrypt)
      flip_index = len(temp_ciphertext) - block_size
      intermediate_block = b''
      # iterate through each byte of each block, and simultaneously, pkcs7 padding bytes
      for current_padding_byte in range(1, block_size + 1):
         original_byte = prev_block[-current_padding_byte]
         if current_padding_byte != 1:
            temp_ciphertext[flip_index - (current_padding_byte - 1):flip_index] = helpers.sxor(intermediate_block,
                                                                                       bytes([current_padding_byte]) * (
                                                                                                  current_padding_byte - 1))
         for char in charset:
            if verbose and hollywood:
               # Silly hollywood style visualization of decryption process
               current_block = helpers.sxor(intermediate_block, prev_block[:-(current_padding_byte - 1)])
               chaff = bytes([char]) * (block_size - current_padding_byte)
               sys.stdout.write("\r" + helpers.bytes2str(helpers.output_mask(current_block + chaff, hollywood_mask)))
               sys.stdout.flush()
            new_byte = char ^ current_padding_byte ^ original_byte
            temp_ciphertext[flip_index - current_padding_byte] = new_byte
            if padding_oracle(bytes(temp_ciphertext)) == True:
               # Either we have a padding of "\x01" or some other valid padding.
               # If we're flipping the last byte, flip the second to last byte just to be sure.
               if current_padding_byte == 1:
                  temp_ciphertext[flip_index - 2] = temp_ciphertext[flip_index - 2] ^ 1
                  if padding_oracle(bytes(temp_ciphertext)) == True:
                     # Current last decrypted byte is 0x01
                     intermediate_byte = 0x01 ^ new_byte
                     break
               else:
                  intermediate_byte = current_padding_byte ^ new_byte
                  break
            if char == charset[-1]:
               # Right now if we fail to decrypt a byte we bail out.
               # TODO: Do something better? Is there something better?
               print("\r[!] Could not decrypt a byte. Bailing out.")
         intermediate_block = bytes([intermediate_byte]) + intermediate_block
      if verbose:
         print(f"\r[+] Decrypted block: {helpers.sxor(prev_block,intermediate_block)}")
      plaintext += helpers.sxor(prev_block, intermediate_block)
      prev_block = block_to_decrypt

   return plaintext


def cbcr(new_plaintext, oracle, block_size, is_padding_oracle=False, verbose=False):
   '''
   Duong & Rizzo's CBC-R technique for turning a CBC mode block
   cipher decryption oracle into an encryption oracle
   
   Parameters:
   ``bytes`` new_plaintext - Plaintext to encrypt using the CBCR technique
   ``function`` oracle - A function that calls out to either a CBC decryption oracle
      or CBC padding oracle. It should take a single ``bytes`` parameter as the ciphertext
      and return either ``True`` for good padding and ``False`` for bad padding if it
      is a padding oracle, or return the decrypted data as ``bytes`` if it is a full 
      decryption oracle.
   ``int`` block_size - block size of cipher in use
   ``bool`` is_padding_oracle - Indicates whether the oracle function provided is a
      padding oracle
   ``bool`` verbose - Provide verbose output

   Returns:
   ``bytes`` The encrypted version of ``new_plaintext``
   '''
   new_plaintext = helpers.pkcs7_pad(new_plaintext, block_size)

   def __padding_decryption_oracle(ciphertext):
      return padding_oracle_decrypt(oracle, ciphertext, block_size, iv=b"\x00" * block_size)

   if is_padding_oracle:
      decrypt = __padding_decryption_oracle
   else:
      decrypt = oracle
   padding_block = b''
   null_block = new_ciphertext = utility_block = b"\x00" * block_size
   # If we have a decryption oracle, we need to prevent padding errors with a valid padding block.
   if is_padding_oracle == False:
      most_of_junk_block = b"\x00" * (block_size - 1)
      for char in [x.to_bytes(1, 'big') for x in range(256)]:
         junk_block = most_of_junk_block + char
         if decrypt(junk_block + null_block) != False:
            padding_block = junk_block + null_block
            break

   plaintext_blocks = helpers.split_into_blocks(new_plaintext, block_size)[::-1]
   if verbose:
      print("[+] Got a valid padding block, continuing with CBC-R.")
      num_blocks = len(plaintext_blocks)
      count = 0
   for plaintext_block in plaintext_blocks:
      if verbose:
         count += 1
         sys.stdout.write('\rEncrypting block %d of %d' % (count, num_blocks))
      intermediate_block = decrypt(null_block + utility_block + padding_block)[block_size:block_size * 2]
      utility_block = helpers.sxor(intermediate_block, plaintext_block)
      new_ciphertext = utility_block + new_ciphertext
   return new_ciphertext


def break_single_byte_xor(ciphertext, num_answers=20, pt_freq_table=frequency.frequency_tables['english'],
                          detect_words=True):
   '''
   Return a list of likely successful single byte XOR decryptions sorted by score

   Inputs:
   ``bytes`` ciphertext - Ciphertext to attack
   ``int`` num_answers - maximum number of answers to return
   ``dict`` pt_freq_table - A frequency table for the expected plaintext, as generated
      by ``generate_frequency_table()``
   ``bool`` detect_words - Whether to use word detection for scoring results

   Returns:
   ``[bytes, ...]`` The ``num_answers`` best answers, sorted by similarity to expected plaintext

   Raises:
   ``ValueError`` if ``num_answers`` is larger than 256.
   '''
   if num_answers > 256:
      raise ValueError('num_answers should not be higher than 256')

   answers = {}
   ciphertext_len = len(ciphertext)
   potential_keys = range(256)

   for key in potential_keys:
      answer = helpers.sxor(ciphertext, bytes([key]) * ciphertext_len)
      answers[answer] = (helpers.detect_plaintext(answer, pt_freq_table=pt_freq_table, detect_words=detect_words), key)
   # Return the best resulting plaintexts and associated score sorted by score
   return sorted(list(answers.items()), key=lambda x: x[1])[:num_answers]


def break_multi_byte_xor(ciphertext, max_keysize=40, num_answers=5, pt_freq_table=frequency.frequency_tables['english'],
                         verbose=False, min_keysize=2):
   '''
   Return a list of likely successful multi-byte XOR decryptions sorted by score

   Inputs:
   ``bytes`` ciphertext - Ciphertext to attack
   ``int`` max_keysize - Largest keysize to try
   ``int`` min_keysize - Smallest keysize to try
   ``int`` num_answers - maximum number of answers to return
   ``dict`` pt_freq_table - A frequency table for the expected plaintext, as generated
      by ``generate_frequency_table()``
   ``bool`` verbose - Show progress in the attack

   Returns:
   ``[bytes, ...]``
   '''
   pt_freq_table_single_chars = dict([x for x in list(pt_freq_table.items()) if len(x[0]) == 1])
   edit_distances = {}
   for keysize in range(min_keysize, max_keysize + 1):
      ciphertext_chunks = helpers.split_into_blocks(ciphertext, keysize)
      if len(ciphertext_chunks) < 3:
         break
      edit_distances[keysize] = helpers.hamming_distance(ciphertext_chunks[0], ciphertext_chunks[1])
      edit_distances[keysize] += helpers.hamming_distance(ciphertext_chunks[1], ciphertext_chunks[2])
      edit_distances[keysize] += helpers.hamming_distance(ciphertext_chunks[0], ciphertext_chunks[2])
      edit_distances[keysize] /= (keysize * 3.0)
   best_keysizes = sorted(list(edit_distances.items()), key=operator.itemgetter(1))[0:num_answers]
   best_keysizes = [keysize[0] for keysize in best_keysizes]
   answers = {}
   if verbose:
      chunks_to_process = sum(best_keysizes)
      current_chunk = 1
   for best_keysize in best_keysizes:
      if verbose:
         print("Trying keysize %d" % best_keysize)
      ct_chunks = []
      for offset in range(best_keysize):
         ct_chunks.append(ciphertext[offset::best_keysize])
      best_key = b''
      for ct_chunk in ct_chunks:
         if verbose:
            sys.stdout.write("\rProcessing chunk %d of %d" % (current_chunk, chunks_to_process))
            sys.stdout.flush()
            current_chunk += 1
         best_key += bytes(
            [break_single_byte_xor(ct_chunk, pt_freq_table=pt_freq_table_single_chars, detect_words=False)[0][1][1]])
      answers[best_key] = helpers.sxor(ciphertext, best_key * ((len(ciphertext) // best_keysize) + 1))
      if verbose:
         print('')
   return sorted(list(answers.values()), key=lambda x: helpers.detect_plaintext(x, pt_freq_table=pt_freq_table))[:num_answers]


def break_many_time_pad(ciphertexts, pt_freq_table=frequency.frequency_tables['single_english'], accuracy=50,
                        verbose=False):
   '''
   Takes a list of ciphertexts XOR'ed with the same unknown set of bytes
   and breaks them by applying single byte xor analysis technique to
   corresponding bytes in each ciphertext.
   
   Useful for:
   OTP with fixed key
   Stream ciphers with fixed key/IV
   Multi-byte XOR with fixed key
   Block ciphers in a stream mode (CTR, GCM, etc) with fixed key/IV

   Inputs:
   ``[bytes, ...]`` ciphertexts - A list of ciphertexts to attack
   ``dict`` pt_freq_table - A frequency table matching the expected frequency
      distribution of the correct plaintext, as generated by
      ``generate_frequency_table()``. Use only frequency tables with
      frequencies for single characters.
   ``int`` accuracy - A number from 1-100 to balance between speed and accuracy
   ``bool`` verbose - Whether or not to show progress

   Returns:
   ``[bytes, ...]`` An array of the best candidate decryption for each ciphertext represented as strings
   '''

   def right_pad_with_none(array, length):
      array_tmp = []
      for item in array:
         item_list = list(item)
         item_list.extend([None] * (length - len(item_list)))
         array_tmp.append(item_list)
      return array_tmp

   # Can't do this with <2 samples
   if len(ciphertexts) < 2:
      if verbose:
         print('[!] This attack requires two or more samples.')
      return False

   # Check accuracy and convert to 1-256
   accuracy = int(accuracy * 2.56)  # 2.56 = 256 * 0.01, result is same as converting to % of 256

   # Need to truncate the longest ciphertext to the length of the second longest
   longest_ct_len = max([len(x) for x in ciphertexts])
   second_longest_ct_len = max([len(x) for x in [x for x in ciphertexts if len(x) <= longest_ct_len]])
   if longest_ct_len != second_longest_ct_len:
      for i in range(len(ciphertexts)):
         if len(ciphertexts[i]) > longest_ct_len:
            ciphertexts[i] = ciphertexts[i][:second_longest_ct_len]

   # Pad the other ciphertexts out with None
   ciphertexts = right_pad_with_none(ciphertexts, second_longest_ct_len)

   zipped_plaintexts = []
   # Separate ciphertext bytes into groups positionally
   zipped_ciphertexts = list(zip(*ciphertexts))
   if verbose:
      num_slices = len(zipped_ciphertexts)
      num_current_slice = 0
   for zipped_ciphertext in zipped_ciphertexts:
      if verbose:
         num_current_slice += 1
         sys.stdout.write("\rBrute forcing slice %d of %d" % (num_current_slice, num_slices))
         sys.stdout.flush()
      # Remove padding for single byte XOR solve
      joined_zipped_ciphertext = b''.join([bytes([x]) for x in zipped_ciphertext if x != None])
      result = break_single_byte_xor(joined_zipped_ciphertext, num_answers=accuracy, pt_freq_table=pt_freq_table,
                                     detect_words=False)[0][0]
      result_tmp = list(result)
      result = []
      # Add it back for rearranging
      for index in range(len(zipped_ciphertext)):
         if zipped_ciphertext[index] != None:
            result.append(result_tmp.pop(0))
         else:
            result.append(None)
      zipped_plaintexts.append(result)
   if verbose:
      print('')
   final_result = []
   for plaintext in zip(*zipped_plaintexts):
      final_result.append(b''.join([bytes([char]) for char in plaintext if char != None]))

   return final_result


def detect_hash_format(words, hashes):
   '''
   Take a list of bytestrings, permute and hash them to determine
   some hash like md5("username:password:userid")
   
   Matches against list of hashes provided in raw or hex form as "hashes" param

   Parameters:
   ``[bytes, ...]`` words - A list of words that may be in the plaintext
   ``[bytes, ...]`` hashes - A set of captured hashes to check against

   Returns:
   ``bytes, str`` as (matching_plaintext, hash_type), or
   ``False`` for no match
   '''
   num_words = len(words)
   if len(words) > 7:
      print('This will take a very long time. Are you sure? (y/n)')
      if sys.stdin.read(1).lower() != 'y':
         return False

   if all([helpers.is_hex_encoded(each_hash) for each_hash in hashes]):
      hashes = [unhexlify(x) for x in hashes]

   for inhash in hashes:
      hash_len = len(inhash)
      for num in range(1, num_words + 1):
         for delimiter in [b'', b':', b';', b'|', b',', b'-', b' ']:
            for candidate in [delimiter.join(permutation) for permutation in itertools.permutations(words, num)]:
               if hash_len == 16:
                  if Crypto.Hash.MD5.new(candidate).digest() == inhash:
                     return (candidate, 'md5')
                  if Crypto.Hash.MD4.new(candidate).digest() == inhash:
                     return (candidate, 'md4')
                  if Crypto.Hash.MD2.new(candidate).digest() == inhash:
                     return (candidate, 'md2')
               elif hash_len == 20:
                  if Crypto.Hash.RIPEMD.new(candidate).digest() == inhash:
                     return (candidate, 'ripemd-160')
                  if Crypto.Hash.SHA1.new(candidate).digest() == inhash:
                     return (candidate, 'sha-1')
               elif hash_len == 28:
                  if Crypto.Hash.SHA224.new(candidate).digest() == inhash:
                     return (candidate, 'sha-224')
               elif hash_len == 32:
                  if Crypto.Hash.SHA256.new(candidate).digest() == inhash:
                     return (candidate, 'sha-256')
               elif hash_len == 48:
                  if Crypto.Hash.SHA384.new(candidate).digest() == inhash:
                     return (candidate, 'sha-384')
               elif hash_len == 64:
                  if Crypto.Hash.SHA512.new(candidate).digest() == inhash:
                     return (candidate, 'sha-512')
   # nothing matches
   return False


def hastad_broadcast_attack(key_message_pairs, exponent):
   """
   Uses Hastad's broadcast attack to decrypt a message encrypted under multiple
   unique public keys with the same exponent, where the exponent is lower than
   the number of distinct key/ciphertext pairs.

   (This function is based on work by Christoph Egger
   <christoph@christoph-egger.org>
   https://www.christoph-egger.org/weblog/entry/46)

   Parameters:
   ``[(int,int), ...]``` key_message_pairs - should be in the form of a list of 2-tuples like so:
      ``[(ciphertext1, modulus1), (ciphertext2, modulus2), (ciphertext3, modulus3)]``
   ``int`` exponent - the exponent e of the public keys

   Returns:
   ``int`` the message
   """
   x, n = helpers.chinese_remainder_theorem(key_message_pairs)
   realnum = int(helpers.nroot(x, exponent))

   return realnum


def dsa_repeated_nonce_attack(r, msg1, s1, msg2, s2, n, verbose=False):
   '''
   Recover k (nonce) and Da (private signing key) from two DSA or ECDSA signed messages
   with identical k values

   adapted from code by Antonio Bianchi (antoniob@cs.ucsb.edu)
   <http://antonio-bc.blogspot.com/2013/12/mathconsole-ictf-2013-writeup.html>

   Parameters:
   ``bytes`` r (r value of signatures)
   ``bytes`` msg1 (first message)
   ``bytes`` s1 (s value of first signature)
   ``bytes`` msg2 (second message)
   ``bytes`` s2 (s value of second signature)
   ``int`` n (curve order for ECDSA or modulus (q parameter) for DSA)

   Returns:
   ``int, int`` The nonce and private key ``(k, Da)``
   '''
   r = int.from_bytes(r, 'big')
   s1 = int.from_bytes(s1, 'big')
   s2 = int.from_bytes(s2, 'big')
   # convert messages to sha1 hash as number
   z1 = int.from_bytes(Crypto.Hash.SHA1.new(msg1).digest(), 'big')
   z2 = int.from_bytes(Crypto.Hash.SHA1.new(msg2).digest(), 'big')

   sdiff_inv = Cnumber.inverse(((s1 - s2) % n), n)
   k = (((z1 - z2) % n) * sdiff_inv) % n

   r_inv = Cnumber.inverse(r, n)
   da = (((((s1 * k) % n) - z1) % n) * r_inv) % n

   if verbose:
      print("Recovered k:" + hex(k))
      print("Recovered Da: " + hex(da))

   return (k, da)


def retrieve_iv(decryption_oracle, ciphertext, blocksize):
   '''
   Retrieve the IV used in a given CBC decryption by decrypting
   [\\x00*(blocksize*2)][ciphertext] and XORing the first two
   resulting blocks of data.

   People have the strange habit of using a static IV that's
   identical to the key. This function is really useful there >:3

   Parameters:
   ``function`` decryption_oracle - A function that queries a decryption oracle that consumes raw ciphertext as
      ``bytes`` and returns raw plaintext as ``bytes``
   ``bytes`` ciphertext - a ciphertext encrypted in CBC mode that's at least two blocks in length
   ``int`` blocksize - the block size of the cipher in use

   Returns:
   ``bytes`` the IV.
   '''
   if len(ciphertext) < 2 * blocksize:
      return False  # ciphertext must be at least two blocks long
   test_payload = (b"\x00" * (blocksize * 2)) + ciphertext
   test_result = decryption_oracle(test_payload)
   return helpers.sxor(test_result[:blocksize], test_result[blocksize:blocksize * 2])
