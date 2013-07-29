import pwn.crypto.xor as xor

plaintext = "the ciphertext decrypted using the replacement dictionary specified"
print "Plaintext:", plaintext

ciphertext = xor.encrypt_xor_counting(plaintext, 42)
print "Ciphertext:", ciphertext

print "Decrypted:", xor.decrypt_xor_counting(ciphertext, 42)

(key, solution) = xor.crack_xor_counting(ciphertext, start=40, end=45)
print "Cracked:", key, solution
