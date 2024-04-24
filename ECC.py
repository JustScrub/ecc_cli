import random

class ECPoint:
    """
    Point on an Elliptic Curve
    """

    def __init__(self, x, y, space):
        self.x = x
        self.y = y
        self.space = space

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

    def order(self):
        p = self
        n = 1
        while p.x is not None:
            p = p + self
            n += 1
        return n

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

class ECKey:
    """
    Elliptic Curve Key Pair
    """

    def __init__(self, space, generator, pub_key=None):
        if space.is_singular():
            raise ValueError("Singular curve")
        if not space.is_valid(generator):
            raise ValueError("Invalid generator")
        
        self.space = space
        self.generator = generator
        self.order = generator.order()
        self.priv_key = None
        self.pub_key = pub_key

    def generate(self):
        if self.priv_key is not None:
            return
        self.priv_key = random.randint(1, self.order - 1)
        self.pub_key = self.generator * self.priv_key
        return self



def ecdsa_sign(message, key):
    """
    ECDSA Sign
    """

    r,s=0,0
    while r == 0 or s == 0:
        rnd = random.randint(1, key.order - 1)
        r = (key.generator * rnd).x % key.order
        s = pow(rnd,-1,key.order) * (message + key.priv_key * r) % key.order
    return (r, s)

def ecdsa_verify(message, signature, key):
    """
    ECDSA Verify
    """

    r, s = signature
    if r < 1 or r > key.order - 1 or s < 1 or s > key.order - 1:
        return False
    w = pow(s,-1,key.order)
    u1 = message * w % key.order
    u2 = r * w % key.order
    p = key.generator * u1 + key.pub_key * u2
    return r == p.x


if __name__ == "__main__":
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
    signature = ecdsa_sign(message, AKey)

    # ===BOB===
    Akey = ECKey(space, G, pub_key=AKey.pub_key)
    print(ecdsa_verify(message, signature, Akey))
