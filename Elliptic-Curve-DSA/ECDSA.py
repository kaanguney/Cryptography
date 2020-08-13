import random
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256

# mathematical functions to be used in the upcoming functions 
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    if a < 0:
        a = a+m
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
      return x % m

# E is the elliptic curve
def KeyGen(E):
  n = E.order
  P = E.generator
  sA = random.randint(0,n-2) # private key
  QA = sA*P
  return sA, QA


# sA is the private key
# message is sent in bytes, no needto convert
def SignGen(message,E,sA):
  n = E.order # get the order
  P = E.generator
  hashedobj = SHA3_256.new() 
  hashedobj.update(message) # hash here
  int_hash = int.from_bytes(hashedobj.digest(), byteorder='big') # conversion from bytes to integer
  # select random integer k 
  k = random.randint(1,n-1) 
  xr,yr = k*(P.x), k*(P.y)
  r = xr % n
  s = (modinv(k,n)*(int_hash+(sA*r)))%n
  # get the signature
  return s,r

def SignVer(message, s, r, E, QA):
  n = E.order # get the order
  P = E.generator 
  p = E.field
  a = E.a
  b = E.b
  hashedobj = SHA3_256.new() 
  hashedobj.update(message) # hash here
  int_hash = int.from_bytes(hashedobj.digest(), byteorder='big') # conversion from bytes to integer
  u1 = modinv(s,n)*int_hash
  u2 = modinv(s,n)*r
  V = u1*P + u2*QA
  holdx = V.x
  v = holdx % n # get x coordinate 
  if((V.y*V.y)%p == (V.x**3+a*V.x+b)%p):
    return 0
  else:
    return 42 # dummy number

