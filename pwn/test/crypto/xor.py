#!/usr/bin/env python
from pwn.crypto.modern import xor

plaintext = "the ciphertext decrypted using the replacement dictionary specified"
print "Plaintext:", plaintext

print '= SINGLE ======================='
ciphertext = xor.encrypt_xor(plaintext, chr(42))
print "Ciphertext:", ciphertext
print "Decrypted:", xor.decrypt_xor(ciphertext, chr(42))
(key, solution) = xor.crack_xor_single(ciphertext, start=40, end=45)
print "Cracked:", key, solution

print '= COUNTING ====================='
ciphertext = xor.encrypt_xor_counting(plaintext, 42)
print "Ciphertext:", ciphertext
print "Decrypted:", xor.decrypt_xor_counting(ciphertext, 42)
(key, solution) = xor.crack_xor_counting(ciphertext, start=40, end=45)
print "Cracked:", key, solution
