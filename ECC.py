import secrets
from base64 import b64encode, b64decode

class ECPoint:
    """
    Point on an Elliptic Curve
    """

    def __init__(self, x, y, space):
        self.x = x % space.p if x is not None else None
        self.y = y % space.p if y is not None else None
        self.space = space
        self._ord = None
        self._nbits = space.p.bit_length()

    def __add__(self, other):
        if self.x == other.x and self.y == other.y:
            return self.double()
        if self.x == other.x:
            return ECPoint(None, None, self.space)
        m = ((self.y - other.y) * pow((self.x - other.x),-1,self.space.p)) % self.space.p
        x = (m**2 - self.x - other.x) % self.space.p
        y = (m * (self.x - x) - self.y) % self.space.p
        return ECPoint(x, y, self.space)
    
    def double(self):
        m = ((3 * self.x**2 + self.space.a) * pow(2 * self.y, -1, self.space.p)) % self.space.p
        x = (m**2 - 2 * self.x) % self.space.p
        y = (m * (self.x - x) - self.y) % self.space.p
        return ECPoint(x, y, self.space)
    
    def __mul__(self, n):
        if n == 0:
            return ECPoint(None, None, self.space)
        if n == 1:
            return self
        if n % 2 == 0:
            return (self.double() * (n // 2))
        return (self.double() * (n // 2)) + self
    
    def __neg__(self):
        return ECPoint(self.x,
                        (self.space.p-self.y) % self.space.p, 
                        self.space)

    @property
    def order(self):
        if self._ord is not None:
            return self._ord
        p = self
        n = 1
        while p.x is not None:
            p = p + self
            n += 1
        self._ord = n
        return n
    
    def serialize(self):
        return b64encode(  self.x.to_bytes((self._nbits+7)//8, 'big') \
                         + self.y.to_bytes((self._nbits+7)//8, 'big')).decode()
    
    @staticmethod
    def deserialize(b64str, space):
        b = b64decode(b64str)
        x = int.from_bytes(b[:len(b)//2], 'big')
        y = int.from_bytes(b[len(b)//2:], 'big')
        return ECPoint(x, y, space)

def tonelli_shanks(n, p):
    if pow(n, (p - 1) >> 1, p) != 1:
        return None
    
    # 1. factor p-1 on the form q * 2^s (with Q odd)
    Q, S = p - 1, 0
    while Q & 1 == 0:
        Q >>= 1
        S += 1
    if S == 1:
        return pow(n, (p + 1) >> 2, p)
    
    # 2. find a z which is a quadratic non-residue modulo p
    z = 2
    while pow(z, (p - 1) >> 1, p) != p - 1:
        z += 1

    # 3. initialize variables
    M, c, t, R = S, pow(z, Q, p), pow(n, Q, p), pow(n, (Q + 1) >> 1, p)

    # 4. loop
    while True:
        if t == 0:
            return 0
        if t == 1:
            return R
        i, t2 = 1, (t * t) % p
        while t2 != 1:
            i += 1
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (M - i - 1), p)
        M, c, t, R = i, (b * b) % p, (t * b * b) % p, (R * b) % p


class ECSpace:
    """
    Elliptic Curve Space
    p: Prime number
    a: Coefficient a
    b: Coefficient b
    """

    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b

    def is_valid(self, point):
        return (point.y**2) % self.p == (point.x**3 + self.a * point.x + self.b) % self.p
    
    def is_singular(self):
        return (4 * self.a**3 + 27 * self.b**2) % self.p == 0

    def find_y(self, x, sgn=0):
        y = tonelli_shanks((x**3 + self.a * x + self.b) % self.p, self.p)
        if y is None:
            return None
        return y if sgn == 0 else self.p - y
    
    def find_x(self, y, niters=1000, srange=None):
        """
        Attempt to find x given y
        y: y-coordinate
        niters: Number of iterations of Newton's method, default 1000
        srange: Search range [x-srange, x+srange], x if found by newton's method; default [0, p]
        """
        y2 = y*y % self.p
        x = 1
        for _ in range(niters):
            x = x - ((x**3 + self.a * x + self.b - y2) // (3*x**2 + self.a))
            x %= self.p
        
        srange = srange if srange is not None else self.p//2
        for i in range(srange + 1):
            if self.is_valid(ECPoint(x+i, y, self)):
                return x+i
            if self.is_valid(ECPoint(x-i, y, self)):
                return x-i
        return None

class ECKey:
    """
    Elliptic Curve Key Pair
    """

    def __init__(self, space, generator, pub_key=None, priv_key=None):
        if space.is_singular():
            raise ValueError("Singular curve")
        if not space.is_valid(generator):
            raise ValueError("Invalid generator")
        
        self.space = space
        self.generator = generator
        self.order = generator.order
        self.priv_key = priv_key
        self.pub_key = pub_key

    def generate(self):
        if self.priv_key is not None:
            self.pub_key = self.generator * self.priv_key
            return self
        self.pub_key = ECPoint(None, None, self.space)
        while self.pub_key.x is None:
            self.priv_key = secrets.randbelow(self.order)
            self.pub_key = self.generator * self.priv_key
        return self

space_codes = {
    "secp256k1": (ECSpace(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
                          0x0, 0x7),
                  (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                   0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
                   0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
}

def load_space(space):
    if space not in space_codes:
        raise ValueError("Unknown space")
    sp = space_codes[space][0]
    generator = ECPoint(*space_codes[space][1], sp)
    generator._ord = space_codes[space][2]
    return sp, generator

class ECDSA:

    def __init__(self, key):
        self.key = key

    def sign(self, message):
        r,s=0,0
        while True:
            rnd = secrets.randbelow(self.key.order)

            r = (self.key.generator * rnd).x 
            if not r: continue # r cannot be None
            r = r % self.key.order
            if not r: continue # r cannot be 0
            s = (pow(rnd,-1,self.key.order) * (message + self.key.priv_self.key * r)) % self.key.order
            if not s: continue # s cannot be 0
            break
        return (r, s)

    def verify(self, message, signature):
        if not self.key.space.is_valid(self.key.pub_self.key):
            return False
        r, s = signature
        if r < 1 or r > self.key.order - 1 or s < 1 or s > self.key.order - 1:
            return False
        w = pow(s,-1,self.key.order)
        u1 = message * w % self.key.order
        u2 = r * w % self.key.order
        p = self.key.generator * u1 + self.key.pub_self.key * u2
        return r == p.x % self.key.order

class ECDH:
    """
    Elliptic Curve Diffie-Hellman
    """

    def __init__(self, space, generator):
        self.space = space
        self.generator = generator
        self.key = None

    def generate(self):
        self.key = ECKey(self.space, self.generator).generate()
        return self.key
    
    def shared_secret(self, pkey):
        return pkey * self.key.priv_key

if __name__ == "__main__":
    cv,g = load_space('secp256k1')
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    y = cv.find_y(x)
    assert y is not None
    P = ECPoint(x, y, cv)
    print(P.x, P.y)
    print(cv.find_x(P.y, 10000000))
    exit()


    p = 37
    a = 2
    b = 7
    space = ECSpace(p, a, b)
    x, G = 3, None
    print("Finding a generator...")
    for y in range(1, p):
        if space.is_valid(ECPoint(x, y, space)):
            print("Generator found!")
            G = ECPoint(x,y, space)
            break

    # ===ALICE===
    AKey = ECKey(space, G).generate()
    message = 12
    signature = ECDSA(AKey).sign(message)

    # ===BOB===
    Akey = ECKey(space, G, pub_key=AKey.pub_key)
    ECDSA(Akey).verify(message, signature)