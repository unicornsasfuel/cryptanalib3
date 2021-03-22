"""
Cryptanalib3 - A series of useful functions for cryptanalysis
by Daniel "unicornFurnace" Crowley

dependencies - PyCryptodome
"""
from . import hashes
import struct

def pad_sha1(msg, length):

    padding_length = len(msg) + length
    padding = b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    padding += b'\x00' * ((56 - (padding_length + 1) % 64) % 64)

    # append length of message (before pre-processing),
    # in bits, as 64-bit big-endian integer
    message_bit_length = padding_length * 8
    padding += struct.pack(b'>Q', message_bit_length)

    return padding


def pad_md4(msg, length):

    l = len(msg) + length
    padding = b'\x80' + b'\x00' * ((55 - l) % 64) + struct.pack("<Q", l * 8)

    return padding


def sha1_extend(msg, length, append, hsh):

    """
    Hash length extension with SHA1: works on challenges of the type

    sha1(secret || message)

    Inputs:
    ``bytes`` msg - known message
    ``int`` length - secret key length, your best guess
    ``bytes`` append - value to append to the hash
    ``bytes`` hsh - original hash.

    Returns:
    ``bytes`` forged_hash - resulting hash
    Depends on modified sha1 algorithm.

    This calculates a glue padding with the SHA1 scheme.
    Other kinds of padding could be implemented here in the future.
    """

    a = int(hsh[0:8], 16)
    b = int(hsh[8:16], 16)
    c = int(hsh[16:24], 16)
    d = int(hsh[24:32], 16)
    e = int(hsh[32:40], 16)

    padding = pad_sha1(msg, length)
    attack = padding + append

    payload = msg + attack
    payload_length = len(padding) + len(msg) + length
    forged_hash = hashes.extend(append, payload_length, a, b, c, d, e)

    return forged_hash


def md4_extend(msg, length, append, hsh):

    """
    Hash length extension with MD4: works on challenges of the type

    md4(secret || message)

    Inputs:
    ``bytes`` msg - known message
    ``int`` length - secret key length, your best guess
    ``bytes`` append - value to append to the hash
    ``bytes`` hsh - original hash.

    Returns:
    ``bytes`` forged_hash - resulting hash
    Depends on modified md4 algorithm.

    This calculates a glue padding with the MD4 scheme.
    Other kinds of padding could be implemented here in the future.
    """
    a = int(hsh[0:8], 16)
    b = int(hsh[8:16], 16)
    c = int(hsh[16:24], 16)
    d = int(hsh[24:32], 16)

    padding = pad_md4(msg, length)
    payload = msg + padding + append

    """
    calculates the correct parameter length for extend(),
    which is len(key + msg + original padding).
    """
    payload_length = len(padding) + len(msg) + length
    forged_hash = hashes.MD4(size=int(payload_length / 64), h=[a, b, c, d]).add(append)

    return forged_hash.hexdigest()

