from ecc_imp import ecc

def bench():
    p = 37
    a = 2
    b = 7
    space = ecc.ECSpace(p, a, b)
    x, G = 3, None
    print("Finding a generator...")
    for y in range(1, p):
        if space.is_valid(ecc.ECPoint(x, y, space)):
            print("Generator found!")
            G = ecc.ECPoint(x,y, space)
            break

    # ===ALICE===
    AKey = ecc.ECKey(space, G).generate()
    message = 12
    signature = ecc.ecdsa_sign(message, AKey)

    # ===BOB===
    Akey = ecc.ECKey(space, G, pub_key=AKey.pub_key)
    return ecc.ecdsa_verify(message, signature, Akey)

if __name__ == "__main__":
    for _ in range(100):
        if not bench():
            print("Failed")
            break
    else:
        print("Success")