"""
Tools for working with XOR-ciphers.
"""

from itertools import cycle, imap
import string

from pwn.crypto import freq
from pwn.crypto import util

def encrypt_xor(plaintext, key):
    if isinstance(plaintext, basestring):
        plaintext = [ord(c) for c in plaintext]
    if isinstance(key, basestring):
        key = [ord(c) for c in key]
    ciphertext = imap(lambda b,k: b ^ k, plaintext, cycle(iter(key)))
    return "".join([chr(c) for c in ciphertext])

def decrypt_xor(ciphertext, key):
    return encrypt_xor(ciphertext, key)

def encrypt_xor_counting(plaintext, start):
    return encrypt_xor(plaintext, [(i+start) % 0xFF for i in range(len(plaintext))])

def decrypt_xor_counting(ciphertext, start):
    return encrypt_xor(ciphertext, [(i+start) % 0xFF for i in range(len(ciphertext))])

def crack_xor_single(ciphertext, start=0x01, end=0xFF, frequencies=freq.english):
    candidates = [encrypt_xor(ciphertext, chr(i)) for i in range(start, end+1)]
    print candidates
    #_, plaintext = util.best_scoring_text(candidates, language)
    distances = []
    for candidate in candidates:
        candidate_freq = freq.text(candidate)
        distances.append(util.squared_differences(candidate_freq, frequencies))
    guess = distances.index(min(distances))
    return (start + guess, candidates[guess])

def crack_xor_repeating():
    pass

def crack_xor_counting(ciphertext, start=0x01, end=0xFF, frequencies=freq.english):
    candidates = [encrypt_xor_counting(ciphertext, i) for i in range(start, end+1)]
    distances = []
    for candidate in candidates:
        candidate_freq = freq.text(candidate)
        distances.append(util.squared_differences(candidate_freq, frequencies))
    guess = distances.index(min(distances))
    return (start + guess, candidates[guess])
