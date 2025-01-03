from Crypto.Util.number import *

def generate_key():
    while True:
        p = getPrime(512)
        q = 2 * p + 1
        if isPrime(q):
            break
    n = p * q
    e = 65537
    d = inverse(e, (p-1)*(q-1))
    return n, e, d

n, e, d = generate_key()
e = 65537

flag = open("flag.txt", "rb").read()

m = bytes_to_long(flag)
c = pow(m, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")