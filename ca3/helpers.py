"""
Cryptanalib - A series of useful functions for cryptanalysis
by Daniel "unicornFurnace" Crowley

dependencies - PyCryptodome
"""
# noinspection PyPackageRequirements
from Crypto.Util import number
from Crypto.Util import strxor
from Crypto.Util import Padding
from Crypto.PublicKey import RSA

import decimal
import math

from . import frequency
import zlib

from base64 import b64decode, b64encode
from binascii import hexlify, unhexlify

lowercase_letters = [b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z']
uppercase_letters = [b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z']
digits = [b'1', b'2', b'3', b'4', b'5', b'6', b'6', b'7', b'8', b'9', b'0']

#------------------------------------
# Helper functions
# 
# This section contains various functions that are not terribly
# useful on their own, but allow other functionality to work
#------------------------------------

def birthday_calc(possibilities, samples=None, likelihood=None):
   """
   Given the number of possible values in a system, and a likelihood, generate the
   approximate number of randomly generated samples needed to achieve a single collision on average
   with the likelihood provided.

   This can be useful for determining the maximum number of messages that can be sent before key rotation should occur, given an acceptable likelihood of collision (e.g. for 128-bit IVs, with a 10% acceptable collision rate, a maximum of 8467859900595397632 messages should be sent before key rotation.)

   Inputs:
   ``int`` possibilities - the number of distinct possible values in the system (e.g. for a 128 bit IV, 2**128)
   ``int`` samples - the number of samples that could possibly collide
   ``float`` likelihood - the probability that exactly two samples have the same value (i.e. one collision)
  
   Returns:
   If ``samples`` is ``None``, return the number of samples needed to reach the provided ``likelihood`` of a collision as an ``int``, given the provided ``possibilities``.
   If ``likelihood`` is ``None``, return the likelihood of a collision given the number of samples and ``possibilities``.

   Raises:
   ``InputError`` if both ``samples`` and ``likelihood`` are ``None``.
   """
   if samples == None:
      if likelihood == None:
         raise InputError("Please provide either a number of samples or likelihood of collision.")
      return int(math.sqrt(2*possibilities*math.log(1/(1-likelihood))))
   else:
      return 1-(math.e ** (-(samples**2)/(2*possibilities)))


def bytes2str(inbytes):
   '''
   Convert bytes directly to a string containing the exact same sequence.
   
   Inputs:
   ``bytes`` inbytes

   Outputs:
   ``str``
   '''
   return ''.join([chr(x) for x in inbytes])

def str2bytes(instring):
   '''
   Convert a string directly to bytes containing the exact same sequence.

   Inputs:
   ``str`` instring

   Outputs:
   ``bytes``
   '''
   return b''.join([bytes([ord(x)]) for x in instring])

def nroot(x, n):
   """
   Return integer nth root of x.

   Inputs:
   ``int`` x, the number to operate on
   ``int`` n, the root to take (e.g. 3 for cube root, 7 for 7th root)

   Outputs:
   ``int``
   """
   if n <= 0:
      raise ValueError("can't do negative or zero root")

   decimal.getcontext().prec = max(30,len(str(x)))
   approx_root = decimal.Decimal(x) ** (decimal.Decimal(1) / decimal.Decimal(n))
   if pow(floor(approx_root),n) == x:
      return floor(approx_root)
   else:
      return ceil(approx_root)

def floor(number):
   """
   Return the closest integer <= number.
  
   Inputs:
   ``float`` number

   Outputs:
   ``int``
   """
   return int(number // 1)

def ceil(number):
   """
   Return the closest integer >= number.

   Inputs:
   ``float`` number

   Outputs:
   ``int``
   """
   floored = number // 1
   if number == floored:
      return int(number)
   else:
      return int(floored + 1)

def bit_length(input_num):
   """
   Return the bit length of input.
   EX: 7 (0b111) has length 3
   EX: 8 (0b1000) has length 4

   Inputs:
   ``int`` input_num

   Outputs:
   ``int``
   """
   # just use the pycryptodome function for this
   return number.size(int(input_num))

# Blinding and unblinding funcs taken graciously from PyCrypto PubKey/RSA/_slowmath.py
def rsa_blind(message, randint, exponent, modulus):
   """
   Return message RSA-blinded with integer randint for a keypair
   with the provided public exponent and modulus.

   Inputs:
   ``int`` message, the plaintext or ciphertext in integer form
   ``int`` randint, the blinding number
   ``int`` exponet, the RSA public exponent
   ``int`` modulus, the RSA public modulus

   Outputs:
   ``int`` the message, RSA-blinded
   """
   return (message * pow(randint, exponent, modulus)) % modulus

def rsa_unblind(message, randint, modulus):
   """
   Return message RSA-unblinded with integer randint for a keypair
   with the provided modulus.
  
   Inputs:
   ``int`` message, the plaintext or ciphertext in integer form
   ``int`` randint, the blinding number
   ``int`` modulus, the RSA public modulus

   Outputs:
   ``int`` the message, RSA-unblinded
   """
   return number.inverse(randint, modulus) * message % modulus

def check_rsa_key(sample):
   """
   Returns a 3-tuple (is_rsa_key, has_private_component, n_bit_length)
   
   is_rsa_key - a bool indicating that the sample is, in fact, an RSA key
      in a format readable by Crypto.PublicKey.RSA.importKey
   has_private_component - a bool indicating whether or not d was in the
      analyzed key, or false if the sample is not an RSA key
   n_bit_length - an int representing the bit length of the modulus found
      in the analyzed key, or False if the sample is not an RSA key
   """
   has_private_component = n_bit_length = False

   try:
      rsakey = RSA.importKey(sample.strip())
      is_rsa_key = True
      if rsakey.has_private():
         has_private_component = True
      n_bit_length = bit_length(rsakey.n)
   # Don't really care why it fails, just want to see if it did
   except:
      is_rsa_key = False
   return (is_rsa_key, has_private_component, n_bit_length)
      

def show_histogram(frequency_table, width=80, sort=True):
   '''
   Take a frequency distribution, such as one generated by
   generate_frequency_table() and represent it as a histogram with the
   specified width in characters

   frequency_table - A frequency distribution
   width - The width in characters for the histogram
   sort - (bool) Sort the histogram by frequency value?
   '''
   max_value = max(frequency_table.values())
   normalizing_multiplier = width / max_value

   if sort:
      frequency_table = sorted(list(frequency_table.items()),key=lambda k_v: (k_v[1],k_v[0]), reverse=True)
   else:
      frequency_table = list(frequency_table.items())

   print(f'0%{" " * (width-6)}{max_value*100}%')
   print(f"{'-' * width}")
   
   for key, value in frequency_table:
      freq_bars = int(value * normalizing_multiplier)
      if freq_bars != 0:
         print(f"{bytes2str(key)}|{'=' * freq_bars}")

def is_base64_encoded(sample):
   '''
   Check if a sample is likely base64-encoded
   
   Inputs
   ``bytes`` sample - The sample to evaluate

   Outputs:
   ``bool`` True if the sample is base64-encoded, False otherwise
   '''
   base64chars = b'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM'
   base64chars += b'1234567890\t\r\n '
   base64chars += b'/+='
   # Turns out a lot of crazy things will b64-decode happily with
   # sample.decode('base64'). This is the fix.
   if any([char not in base64chars for char in sample]):
      return False
   try:
      b64decode(sample)
      return True
   except:
      return False


def is_hex_encoded(sample):
   '''
   Check if a sample hex-decodes without error

   Inputs:
   ``bytes`` sample - The hex-encoded sample to evaluate
 
   Outputs:
   ``bool`` True if sample is hex-encoded, False otherwise
   '''
   try:
      unhexlify(sample)
      return True
   except:
      return False



def is_zlib_compressed(sample):
   '''
   Check if some sample can be zlib decompressed without error
   
   Inputs:
   ``bytes`` sample - The sample to evaluate

   Outputs:
   ``bool`` True if sample is zlib compressed, False otherwise
   '''
   try:
      zlib.decompress(sample)
      return True
   except:
      return False


def detect_polybius(sample):
   '''
   Detect the use of the polybius cipher
   
   Inputs:
   ``bytes`` sample - The sample to evaluate

   Outputs:
   ``bool`` True if sample is likely Polybius encrypted, False otherwise
   '''
   correct_charset = all([char in b' 01234567' for char in sample])
   correct_length = len([x for x in sample if x in b'01234567']) % 2 == 0
   return correct_charset and correct_length


def monte_carlo_pi(sample):
   '''
   Monte Carlo Pi estimation test
   
   Good for determining the randomness of data, especially when looking at compressed
   vs encrypted data.
   
   Returns the estimated value of Pi. The closer the returned value to the value of Pi,
   the more entropy in the data.
   
   Inputs:
   ``bytes`` sample - The sample to evaluate

   Outputs:
   ``float`` - the estimated value of Pi 
   '''
   # cut down our sample to a multiple of four bytes in length so we
   # can take two two-byte samples for x/y coords
   if len(sample) < 4:
      return False
   if (len(sample) % 4) != 0:
      sample = sample[:-(len(sample)%4)]
   coords = []
   hits = 0
   for offset in range(0,len(sample),4):
      # extract four bytes from sample
      subsample = sample[offset:offset+4]
      # interpret the first two bytes as an X value between -32512.5 and 32512.5
      subsample_x = ((subsample[0]*255)+subsample[1])-32512.5
      # map this value down to one between -1.0 and 1.0
      subsample_x /= 32512.5
      # interpret the next two bytes as a Y value between -32512.5 and 32512.5
      subsample_y = ((subsample[2]*255)+subsample[3])-32512.5
      # map this value down to one between -1.0 and 1.0
      subsample_y /= 32512.5
      coords.append((subsample_x,subsample_y))
   for coordinate in coords:
      if coordinate[0]**2 + coordinate[1]**2 <= 1:
         hits += 1
   pi_estimate = 4*(float(hits) / (len(sample)/4))
   return pi_estimate


def check_key_reuse(samples, low_threshold=3.25, high_threshold=4.75):
   '''
   Check for key reuse between two or more messages
   
   Returns a boolean indicating whether two messages have high or low
   bitwise correspondence, which suggests key reuse.
   
   Inputs:
   ``[bytes, bytes, ...]`` samples - Two or more samples for evaluation
   ``float`` low_threshold - The Hamming distance below which key reuse should be reported
   ``float`` high_threshold - The Hamming distance above which key reuse should be reported
  
  
   Outputs:
   ``bool`` 
   '''
   samples = [x for x in samples if len(x) != 0]
   if len(samples) == 1:
      print('Need more than one non-null sample')
      return None
   total_length = total_hamming_distance = 0
   for sample in samples[1:]:
      compare_length = min(len(samples[0]),len(sample))
      sample_hamming_distance = hamming_distance(samples[0],sample)
      total_hamming_distance += sample_hamming_distance
      total_length += compare_length
   mean_hamming_distance = total_hamming_distance / float(total_length)
   return ((mean_hamming_distance < low_threshold) or (mean_hamming_distance > high_threshold))


# TODO: Implement chi square
def is_random(sample, verbose=False, boolean_results=True):
   '''
   Run randomness tests to determine likelihood of data being
   the output of strong crypto or CSPRNG or RNG a la ent
   
   with boolean_results=True
   Returns a boolean indicating whether all tests for randomness have passed
   
   with boolean_results=False
   Returns detailed results about what tests passed/failed

   Inputs:
   ``bytes`` sample - A sample to evaluate for signs of randomness
   ``bool`` verbose - Whether to print information about results or not
   ``bool`` boolean_results - Whether to return True/False or show more details
      on what tests passed or failed

   Outputs:
   If ``boolean_results`` is ``True``, returns a ``bool`` indicating if any tests failed.
   Otherwise, return
   ``{``
      'mean_failed': bool,
      'byte_count_failed': bool,
      'bit_run_failed': bool,
      'monte_carlo_failed': bool,
      'compression_ratio_failed': bool
   }``
   '''
   results = {}
   sample_length = len(sample)
   if sample_length == 0:
      return False
   if sample_length < 100:
      if verbose:
         print('[*] Warning! Small sample size, results may be unreliable.')
   # Arithmetic mean test
   mean = sum([char for char in sample])/float(sample_length)
   if verbose:
      print(('[+] Arithmetic mean of sample is '+str(mean)+'. (127.5 = random)'))
   if ((mean <= 110) or (mean >= 145)):
      results['mean_failed'] = True
      if verbose:
         print('[!] Arithmetic mean of sample suggests non-random data.')
   else:
      results['mean_failed'] = False
   # Byte and digraph count test
   byte_count = generate_frequency_table(sample, [bytes([x]) for x in range(256)])
   min_to_max = max(byte_count.values())-min(byte_count.values())
   if verbose:
      print(('[+] Distance between lowest and highest byte frequencies is '+str(min_to_max)+'.'))
      print('[+] Distance for 100+ random bytes of data generally does not exceed 0.4')
   if min_to_max > 0.4:
      results['byte_count_failed'] = True
      if verbose:
         print('[!] Distance between byte frequencies suggests non-random data.')
   else:
      results['byte_count_failed'] = False
   # Longest bit run test
   binary_message = ''.join(['{0:08b}'.format(char) for char in sample])
   longest_bit_run_threshold = 20
   longest_run = 0
   current_run = 0
   prev_bit = None
   for bit in binary_message:
      if bit == prev_bit:
         current_run += 1
      else:
         current_run = 0
      if current_run > longest_run:
         longest_run = current_run
      prev_bit = bit
   if verbose:
      print(('[+] Longest same-bit run in the provided sample is %s' % str(longest_run)))
      print('[+] This value generally doesn\'t exceed 20 in random data.')
   results['bit_run_failed'] = (longest_run >= longest_bit_run_threshold)
   if results['bit_run_failed'] and verbose:
      print('[!] Long same-bit run suggests non-random data.')
   # Monte Carlo estimation of Pi test
   approximate_pi = 3.141592654
   monte_carlo_pi_value_deviation = abs(approximate_pi - monte_carlo_pi(sample)) 
   results['monte_carlo_failed'] = (monte_carlo_pi_value_deviation > 0.4)
   if verbose:
      print(('[+] Deviation between the approx. value of pi and the one generated by this sample using Monte Carlo estimation is %s' % str(monte_carlo_pi_value_deviation)))
      print('[+] Deviation for 100+ random bytes of data generally does not exceed 0.4.')
   if results['monte_carlo_failed'] and verbose:
      print('[!] Deviation exceeds 0.4. If no other randomness tests failed, this data may be compressed, not encrypted or random.')
   # Compression ratio test
   compression_ratio = len(zlib.compress(sample,9)) / float(len(sample))
   if verbose:
      print(('[+] Zlib best compression ratio is {0:.0f}%'.format(compression_ratio * 100)))
      print('[+] Compression ratio for random data is unlikely to be lower than 95%.')
   results['compression_ratio_failed'] = (compression_ratio <= .95)
   if boolean_results:
      if any(results.values()):
         if verbose:
            print('[!] One or more tests for randomness suggests non-random data.')
            print('[!] This data may be the result of weak encryption like XOR.')
            print('[!] This may also suggest a fixed IV or ECB mode.')
            print('[!] This data may also be simply compressed or in a proprietary format.')
         return False
      else:
         if verbose:
            print('[+] This data has passed all randomness tests performed.')
            print('[+] This suggests data generated by a RNG, CSPRNG, or strong encryption.')
         return True
   else:
      if verbose:
         if sum(results.values()) == 1:
            if results['monte_carlo_failed']:
               print('[+] Only the Monte Carlo Pi generation test has failed. This may indicate that the data is not encrypted, but simply compressed.')
            elif results['bit_run_failed']:
               print('[+] Only the longest-bit-run test has failed. This suggests that certain portions of the data are not encrypted.')
      return results

def gcd(a,b):
   '''
   Wrapper around extended_gcd() that simply returns the GCD alone.

   Inputs:
   ``int`` a, b - Two integers to find common factors for

   Outputs:
   ``int`` The greatest common denominator between the two numbers, which may be 1.
   '''
   return extended_gcd(a,b)[2]


def extended_gcd(a, b): 
   '''
   Euclid's GCD algorithm, but with the addition that the last x and y values are returned.

   Inputs:
   ``int`` a, b - Two integers to find common factors for

   Returns (Last X value, Last Y value, Greatest common divisor)
   '''
   x,y = 0, 1
   lastx, lasty = 1, 0

   while b:
      a, (q, b) = b, divmod(a,b)
      x, lastx = lastx-q*x, x
      y, lasty = lasty-q*y, y

   return (lastx, lasty, a)

def chinese_remainder_theorem(items):
   '''
   The Chinese Remainder Theorem algorithm.

   Inputs:
   ``[(int, int), ...]`` items - A list of 2-tuples such as [(a1, n1),(a2, n2)] that map
      to congruences, i.e.:
      a1 is congruent to x mod n1
      a2 is congruent to x mod n2
 
   Outputs:
   ``(int, int)`` - A 2-tuple of the result of the CRT, and the n values multiplied together.

   Raises:
   ``ValueError`` if inputs are not pairwise co-prime
   '''
   N = 1 
   for a, n in items:
      N *= n

   result = 0 
   for a, n in items:
      m = N//n 
      r, s, d = extended_gcd(n, m)
      if d != 1:
         raise ValueError("Input not pairwise co-prime")
      result += a*s*m

   return result % N, N



def detect_block_cipher(ciphertext):
   '''
   Detect block cipher by length of ciphertext

   Inputs:
   ``bytes`` ciphertext - A sample to be evaluated for common block sizes

   Outputs:
   ``int`` for largest identified block size, or ``False`` if none
   '''
   for candidate_blocksize in [32,16,8]:
      if len(ciphertext) % candidate_blocksize == 0:
         return candidate_blocksize
   return False



def detect_plaintext(candidate_text, pt_freq_table=frequency.frequency_tables['english_letters'], detect_words=True, common_words=frequency.common_words['english'], individual_scores=False):
   '''
   Return score for likelihood that string is plaintext
   in specified language as a measure of deviation from
   expected frequency values (lower is better)

   Inputs:
   ``bytes`` candidate_text - The sample to check for plaintext-like properties
   ``dict`` pt_freq_table - Expected frequency distribution for the plaintext, as generated
      by ``generate_frequency_table()``. If only individual character frequency should
      be matched, ensure you're using a frequency table with only single character
      frequencies. If you're using the built-in tables, these are prefixed with
      ``single_``.
   ``bool`` detect_words - Use a list of strings expected in the correct plaintext,
      aka ``cribs``.
      This can be used in a number of ways. For instance, when attempting to decrypt
      firmware, ``\\x00\\x00\\x00\\x00\\x00`` may be a useful crib. When attempting to
      decrypt a PNG file, ``IHDR``, ``IDAT``, and ``IEND`` are useful cribs.
   ``[bytes, ...]`` common_words - Words that are likely to appear in the plaintext.
      Requires ``detect_words=True``.
   ``bool`` individual_scores - Whether or not to return a tuple with individual scores.

   Outputs:
   ``float`` if ``individual_scores`` is ``False``
   ``(float, int)`` if ``individual_scores`` is ``True``
   '''

   # generate score as deviation from expected character frequency
   pt_freq_table_keys = list(pt_freq_table.keys())
   candidate_dict = generate_frequency_table(candidate_text, pt_freq_table_keys)
   char_deviation_score = 0
   for char in pt_freq_table_keys:
      char_deviation_score += abs(candidate_dict[char]-pt_freq_table[char])

   # generate score as total number of letters in common words found in sample
   word_count_score = 0
   if detect_words:
      word_count_score = count_words(candidate_text, common_words=common_words)
   
   if individual_scores:
      return (char_deviation_score, word_count_score)
   else:
      if word_count_score == 0:
         score = 1
      else:
         score = 1.0/word_count_score
      score += char_deviation_score
      return score


def generate_optimized_charset_from_frequency(freq_table, include_zero_freq=False):
   '''
   Given a character frequency table such as those returned by ``generate_frequency_table()``,
   return ``bytes`` with only single characters sorted by frequency of occurrence descending

   Inputs:
   ``{bytes: float, ...}`` freq_table - a frequency table such as those generated by
      ``generate_frequency_table``.
   ``bool`` include_zero_freq - Whether to include characters with no occurrence in the
      character set

   Returns:
   ``bytes``
   '''
   # Filter out frequency items to only single characters
   single_char_freq_table = dict([x for x in list(freq_table.items()) if len(x[0])==1])
   # Filter out items which never occur
   if not include_zero_freq:
      single_char_freq_table = dict([x for x in list(single_char_freq_table.items()) if x[1] != 0])
   # Sort items by frequency, concatenate characters and return as a single string
   return b''.join([x[0] for x in sorted(list(single_char_freq_table.items()), key=lambda x: x[1], reverse=True)])
   
   

def generate_frequency_table(text,charset):
   '''
   Generate a character frequency table for a given text
   and charset as dict with byte or bytes as key and
   frequency of appearance as value expressed as a decimal
   percentage

   Inputs:
   ``bytes`` text - A sample of plaintext to analyze for frequency data
   ``[bytes, ...]`` charset - The set of items to count in the plaintext
      such as [b'a',b'b',b'c', ... b'z',b'aa',b'ab',b'ac', ... b'zz']

   Outputs:
   ``{bytes: float, ...}`` A dict of key:value pairs where each key is
      a byte sequence and its value is its probability of occurrence from
      0 to 1

   Raises:
   ``ValueError`` if ``text`` is zero-length
   '''
   freq_table = {}
   text_len = len(text)
   if text_len == 0:
      raise ValueError("Text is zero-length.")
   for multigraph in charset:
      freq_table[multigraph] = text.count(multigraph)
   # Normalize frequencies with length of text
   for key in list(freq_table.keys()):
      freq_table[key] /= text_len
   return freq_table

def generate_optimized_charset(text, include_zero_freq=False):
   '''
   Given a sample text, generate a frequency table and
   convert it to a string of characters sorted by frequency
   of appearance in the text. This can be used directly in
   some of the other cryptanalib functions, such as our
   Vaudenay padding oracle decryption function.

   Inputs:
   ``bytes`` text - The corpus of text from which to learn
      frequency data.

   Outputs:
   ``bytes``
   '''

   all_chars = [bytes([b]) for b in range(0,255)]
   freq_table = generate_frequency_table(text, charset=all_chars)
   return generate_optimized_charset_from_frequency(freq_table, include_zero_freq=include_zero_freq)
   
def hamming_distance(sample1, sample2):
   '''
   Calculate and return number of bit edits needed to transform one string into another
   
   Inputs:
   ``bytes`` sample1 - The first sample to compare
   ``bytes`` sample2 - The second sample to compare
  
   Outputs:
   ``int``
   '''
   distance = 0
   for char1, char2 in zip(sample1, sample2):
      for digit1, digit2 in zip('{0:08b}'.format(char1),'{0:08b}'.format(char2)):
         if digit1 != digit2:
            distance += 1
   return distance

def output_mask(text, charset):
   '''
   Output masking - replace all characters besides those in the provided character
   set with dots, and return the result
   
   Inputs:
   ``bytes`` text - output to mask
   ``bytes`` charset - set of acceptable characters

   Outputs:
   ``bytes``
   '''
   all_chars = output_chars = [bytes([x]) for x in range(256)]
   charset = [bytes([x]) for x in set(charset)]
   for charnum in range(256):
      if all_chars[charnum] not in charset:
         output_chars[charnum] = b'.'
   return text.translate(b''.join(output_chars))

def bytes_to_int(inbytes):
   '''
   Take ``bytes`` and convert to ``int``, Big-endian

   Inputs:
   ``bytes`` inbytes - Sample to convert

   Outputs:
   ``int`` 
   '''
   return int(hexlify(inbytes), 16)

def int_to_bytes(inint):
   '''
   Take an ``int`` and convert to ``bytes``

   Inputs:
   ``int`` inint - Number to convert

   Outputs:
   ``bytes``
   '''
   hex_encoded = hex(inint)[2:-1]
   if len(hex_encoded) % 2 == 1:
      return unhexlify('0'+hex_encoded)
   else:
      return unhexlify(hex_encoded)


def split_into_blocks(ciphertext,blocksize):
   '''
   Split a bytestring into blocks of length blocksize

   Inputs:
   ``bytes`` ciphertext - A sample to be split
   ``int`` blocksize - The size in bytes of blocks to output
  
   Outputs:
   ``[bytes, ...]``
   '''
   ciphertext_len = len(ciphertext)
   return [ciphertext[offset:offset+blocksize] for offset in range(0,ciphertext_len,blocksize)]


def sxor(string1, string2):
   '''
   XOR two bytestrings and return the result up to the length
   of the shorter string

   Inputs:
   ``bytes`` string1 - The first sample to be XORed
   ``bytes`` string2 - The second sample to be XORed
 
   Outputs:
   ``bytes``
   '''
   # just use PyCryptodome's sxor func
   str1len = len(string1)
   str2len = len(string2)
   if str1len < str2len:
      return strxor.strxor(string1, string2[:str1len])
   else:
      return strxor.strxor(string1[:str2len], string2)

def count_words(candidate_text, common_words=frequency.common_words['english'], case_sensitive=True):
   '''
   Count the instances of common words in the expected plaintext
   language, return the total number of characters matched in each
   word 

   Inputs:
   ``bytes`` candidate_text - Sample to analyze
   ``[bytes, ...]`` common_words - Sequences expected to appear in the text
   ``bool`` case_sensitive - Whether or not to match case sensitively

   Outputs:
   ``int`` total characters in all words matched
   '''
   score = 0

   for word in common_words:
      if not case_sensitive:
         word = word.lower()
      num_found = candidate_text.count(word)
      if num_found > 0:
         score += num_found * len(word)
      
   return score


def make_polybius_square(password,extended=False):
   '''
   Polybius square generator. Returns a list of strings of equal
   length, either 5x5 or 6x6 depending on whether extended
   Polybius mode is on. Assumes I/J are represented as one letter

   Inputs:
   ``bytes`` password - The password to use when generating the polybius square
   ``bool`` extended - Set to True to use a 6x6 square instead of a 5x5

   Outputs:
   ``[bytes, bytes, bytes, bytes, bytes]`` for a regular Polybius square. Each bytestring
      will be five bytes long.
   ``[bytes, bytes, bytes, bytes, bytes, bytes]`` for extended Polybius. Each bytestring
      will be six bytes long.
   '''
   alphabet = lowercase_letters
   if extended:
      alphabet += digits
   else:
      alphabet = bytes.replace(b''.join(lowercase_letters), b'j', b'')
      password = bytes.replace(password, b'j', b'i')
   if any([x not in alphabet for x in set(password)]):
      return False
   unique_letters = []
   for letter in [bytes([x]) for x in password]:
      if letter not in unique_letters:
         unique_letters.append(letter)
   for letter in unique_letters:
      alphabet = bytes.replace(alphabet, letter, b'')
   for letter in unique_letters[::-1]:
      alphabet = letter + alphabet
   ps = []
   alphabet_len = len(alphabet)
   grid_size = 5 + int(extended) # Not necessary, but looks cleaner
   for index in range(0,alphabet_len,grid_size):
      ps.append(alphabet[index:index+grid_size])
   return ps

def polybius_decrypt(ps, ciphertext):
   '''
   Decrypt given a polybius square (such as one generated
   by ``make_polybius_square()``) and a ``ciphertext``.

   Inputs:
   ``bytes`` ps - A polybius square as generated by ``make_polybius_square()``
   ``bytes`` ciphertext - A bytestring to decrypt

   Outputs:
   ``bytes``
   '''
   ct_len = len(ciphertext)
   if (ct_len % 2) != 0:
      return False
   digraphs = []
   plaintext = b''
   for index in range(0,ct_len,2):
      digraphs.append(ciphertext[index:index+2])
   for digraph in digraphs:
      x = int(chr(digraph[0])) - 1
      y = int(chr(digraph[1])) - 1
      plaintext += bytes([ps[x][y]])
   return plaintext

def detect_ecb(ciphertext):
   '''
   Attempts to detect use of ECB by detecting duplicate blocks using common
   block sizes.

   Inputs:
   ``bytes`` ciphertext - A sample to analyze for the indicators of ECB mode

   Outputs:
   ``(bool, int, bytes)`` A 3-tuple of whether the sample appears to be using ECB,
      the blocksize detected, and the repeated block that indicated ECB mode
   '''
   ciphertext_len = len(ciphertext)
   for blocksize in [32,16,8]:
      if ciphertext_len % blocksize == 0:
         blocks = split_into_blocks(ciphertext,blocksize)
         seen = set()
         for block in blocks:
            if block in seen:
               return (True, blocksize, block)
            else:
               seen.add(block)
   return False, 0, b''


def pkcs7_padding_remove(text, blocksize):
   '''
   PKCS7 padding remove - returns unpadded string if successful, returns False if unsuccessful

   Inputs:
   ``bytes`` text - The text to pkcs7-unpad
   ``int`` blocksize - The blocksize of the text

   Outputs:
   ``bytes``
   '''
   # just call pycryptodome padding function instead
   return Padding.unpad(text, blocksize)

def pkcs7_pad(text, blocksize):
   '''
   PKCS7 padding function, returns text with PKCS7 style padding

   Inputs:
   ``bytes`` text - The text to pkcs7-pad
   ``int`` blocksize - The blocksize of the text

   Outputs:
   ``bytes``
   '''
   # just call pycryptodome padding function instead
   return Padding.pad(text, blocksize)


def derive_d_from_pqe(p,q,e):
   '''
   Given p, q, and e from factored RSA modulus, derive the private component d

   Inputs:
   ``int`` p - The first of the two factors of the modulus
   ``int`` q - The second of the two factors of the modulus
   ``int`` e - The public exponent

   Outputs:
   ``int`` The private exponent d
   '''
   return int(number.inverse(e,(p-1)*(q-1)))

def prime_factors(n):
    '''
    Simple algorithm to factorize n.
    Inputs:
    ``int`` n - The number

    Outputs:
    ``list`` Lists all the tuples of factors and exponents [(factor1, exponent1),..].
    '''
    r = []
    while n % 2 == 0:
        n //= 2
        r.append(2)
    for i in range(3, n // 2, 2):
        if n <= 1:
            break
        while n % i == 0:
            n //= i
            r.append(i)
    return [(x, r.count(x)) for x in set(r)]

def pollard_factor(n):
    '''
    if n is a product of primes p*q, and p-1 is a product of small primes, finds a factor of p-1 and returns.
    Inputs:
    ``int`` n - The number n = p*q

    Outputs:
    ``int`` one factor of p-1.
    '''
    a = 2
    factorial = 2
    for i in range(1, n):
        factorial *= i+1
        r, s, d = extended_gcd(pow(a, factorial, n) - 1, n)
        if d != 1:
            return d

def discrete_log(g, h, p):
    '''
    Straightforward way to bruteforce the discrete log.
    Here to fill a hole to be improved upon later.
    ``int`` p - The size of the prime field
    ``int`` h - The congruence meant to be found
    ``int`` g - The number to be exponentiated

    Outputs:
    ``int`` The discrete log
    '''
    for i in range(1, p):
        n = pow(g, i, p)
        if n == h:
            return i

def find_order(g, p):
    '''
     Find the order of element g in prime field p.
     The order of an element g is N when g^N mod p == 1.
     Not the most optimal way to do this, but the discrete log algos
     assume you have the order of the element beforehand so here we are.
    Inputs:
    ``int`` p - The size of the prime field
    ``int`` g - The number to find the order of

    Outputs:
    ``int`` The order
    '''
    return discrete_log(g, 1, p)

