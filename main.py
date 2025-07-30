from Crypto.Util.number import bytes_to_long, getPrime, inverse

flag = b"SCD{f4k3_fl4g}"

p = getPrime(1024)
q = 7

n = p * q

e = e = 65537

phi = (p - 1) * (q - 1)
d = inverse(e, phi)

flag_int = bytes_to_long(flag)
ciphertext = pow(flag_int, e, n)

print(f"Public modulus (n): {n}")
print(f"Public exponent (e): {e}")
print(f"Encrypted flag: {ciphertext}")

decrypt = pow(ciphertext, d, n)
# print(long_to_bytes(decrypt))
