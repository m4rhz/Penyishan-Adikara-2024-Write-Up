from Crypto.Util.number import long_to_bytes
from math import isqrt

def solve_quadratic(a, b, c):
    # Solve quadratic equation ax^2 + bx + c = 0
    discriminant = b*b - 4*a*c
    if discriminant < 0:
        return None
    
    # We only want the positive root since p is a prime number
    root = (-b + isqrt(discriminant)) // (2*a)
    return root

# Given values
n = 141462798088722051318799729490921841045684289129519401507458481551818501345780972050140869439773419571781243083655675803580035825559100776989995997460352754682544784811123149386346851850688727377614402261954229978269219754312075185083872573296071312565168967164450658906124427063020647048739457948457283284791
e = 65537
c = 95810701202087853841743731093149430655593147683421871799265784567546744027028327006037927756808923742806457516687369724053659801409665809484333704658005178575699287145132631020220338745054190238905155637221474537758319000878100880684173099253778386118547321637286540549815419269314760633502070855820951147798

# Solve 2p^2 + p - n = 0
p = solve_quadratic(2, 1, -n)
print(f"Found p: {p}")

# Calculate q = 2p + 1
q = 2 * p + 1
print(f"Found q: {q}")

# Calculate private key
phi = (p-1) * (q-1)
d = pow(e, -1, phi)

# Decrypt the message
m = pow(c, d, n)
flag = long_to_bytes(m)
print(f"Flag: {flag.decode()}")