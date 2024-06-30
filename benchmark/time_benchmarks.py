import ecpy.curves
from ecc_imp import ecc
import ecpy
import secrets
from time import perf_counter_ns as monotonic_ns

def ecpy_ecdsa_const_msg(msg_len=32, reps=1000):
    from ecpy.curves     import Curve
    from ecpy.keys       import ECPrivateKey
    from ecpy.ecdsa      import ECDSA

    msg    = secrets.token_bytes(msg_len)
    cv     = Curve.get_curve('secp256k1')
    signer = ECDSA()
    Tsg = 0
    Tvr = 0

    for _ in range(reps):
        pv_key = ECPrivateKey(secrets.randbelow(cv.order),cv)
        pu_key = pv_key.get_public_key()
        
        t = monotonic_ns()
        sig = signer.sign(msg,pv_key)
        Tsg += monotonic_ns()-t

        t = monotonic_ns()
        signer.verify(msg,sig,pu_key)
        Tvr += monotonic_ns()-t

    lib,bench = "ecpy","ecdsa_const_msg"
    return f"{lib},{bench}_sign,{Tsg/reps}\n{lib},{bench}_verify,{Tvr/reps}\n"

def ecc_ecdsa_const_msg(msg_len=32, reps=1000):

    msg = secrets.token_bytes(msg_len)
    msg = int.from_bytes(msg, 'big')
    cv, gen = ecc.load_space('secp256k1')
    Tsg = 0
    Tvr = 0

    for _ in range(reps):
        priv =    secrets.randbelow(gen.order)
        key =     ecc.ECKey(cv, gen, priv_key=priv).generate()
        signer =  ecc.ECDSA(key)

        t = monotonic_ns()
        sig = signer.sign(msg)
        Tsg += monotonic_ns()-t

        t = monotonic_ns()
        signer.verify(msg, sig)
        Tvr += monotonic_ns()-t

    lib,bench = "ecc","ecdsa_const_msg"
    return f"{lib},{bench}_sign,{Tsg/reps}\n{lib},{bench}_verify,{Tvr/reps}\n"

def ecpy_ecdsa_var_msg(msg_len=32, reps=1000):
    from ecpy.curves     import Curve
    from ecpy.keys       import ECPrivateKey
    from ecpy.ecdsa      import ECDSA

    cv     = Curve.get_curve('secp256k1')
    signer = ECDSA()
    Tsg = 0
    Tvr = 0

    for _ in range(reps):
        pv_key = ECPrivateKey(secrets.randbelow(cv.order),cv)
        pu_key = pv_key.get_public_key()
        msg    = secrets.token_bytes(msg_len)
        
        t = monotonic_ns()
        sig = signer.sign(msg,pv_key)
        Tsg += monotonic_ns()-t

        t = monotonic_ns()
        signer.verify(msg,sig,pu_key)
        Tvr += monotonic_ns()-t

    lib,bench = "ecpy","ecdsa_var_msg"
    return f"{lib},{bench}_sign,{Tsg/reps}\n{lib},{bench}_verify,{Tvr/reps}\n"

def ecc_ecdsa_var_msg(msg_len=32, reps=1000):
    
        cv, gen = ecc.load_space('secp256k1')
        Tsg = 0
        Tvr = 0
    
        for _ in range(reps):
            priv =    secrets.randbelow(gen.order)
            key =     ecc.ECKey(cv, gen, priv_key=priv).generate()
            signer =  ecc.ECDSA(key)
            msg =     secrets.token_bytes(msg_len)
            msg =     int.from_bytes(msg, 'big')
    
            t = monotonic_ns()
            sig = signer.sign(msg)
            Tsg += monotonic_ns()-t

            t = monotonic_ns()
            signer.verify(msg, sig)
            Tvr += monotonic_ns()-t
    
        lib,bench = "ecc","ecdsa_var_msg"
        return f"{lib},{bench}_sign,{Tsg/reps}\n{lib},{bench}_verify,{Tvr/reps}\n"

def ecpy_ecdsa_const_key(msg_len=32, reps=1000):
    from ecpy.curves     import Curve
    from ecpy.keys       import ECPrivateKey
    from ecpy.ecdsa      import ECDSA

    cv     = Curve.get_curve('secp256k1')
    signer = ECDSA()
    Tsg = 0
    Tvr = 0

    pv_key = ECPrivateKey(secrets.randbelow(cv.order),cv)
    pu_key = pv_key.get_public_key()

    for _ in range(reps):
        msg = secrets.token_bytes(msg_len)
        t = monotonic_ns()
        sig = signer.sign(msg,pv_key)
        Tsg += monotonic_ns()-t

        t = monotonic_ns()
        signer.verify(msg,sig,pu_key)
        Tvr += monotonic_ns()-t

    lib,bench = "ecpy","ecdsa_const_key"
    return f"{lib},{bench}_sign,{Tsg/reps}\n{lib},{bench}_verify,{Tvr/reps}\n"

def ecc_ecdsa_const_key(msg_len=32, reps=1000):
    
        cv, gen = ecc.load_space('secp256k1')
        Tsg = 0
        Tvr = 0
    
        priv =    secrets.randbelow(gen.order)
        key =     ecc.ECKey(cv, gen, priv_key=priv).generate()
        signer =  ecc.ECDSA(key)
    
        for _ in range(reps):
            msg = secrets.token_bytes(msg_len)
            msg = int.from_bytes(msg, 'big')

            t = monotonic_ns()
            sig = signer.sign(msg)
            Tsg += monotonic_ns()-t

            t = monotonic_ns()
            signer.verify(msg, sig)
            Tvr += monotonic_ns()-t

        lib,bench = "ecc","ecdsa_const_key"
        return f"{lib},{bench}_sign,{Tsg/reps}\n{lib},{bench}_verify,{Tvr/reps}\n"

def ecpy_point_add(reps=1000):
    cv = ecpy.curves.Curve.get_curve('secp256k1')
    gen = cv.generator
    T = 0
    for _ in range(reps):
       p1 = secrets.randbelow(cv.order) * gen
       p2 = secrets.randbelow(cv.order) * gen

       t = monotonic_ns()
       p1 + p2
       T += monotonic_ns()-t
    
    lib,bench = "ecpy","point_add"
    return f"{lib},{bench},{T/reps}\n"

def ecc_point_add(reps=1000):
    cv, gen = ecc.load_space('secp256k1')
    T = 0
    for _ in range(reps):
       p1 = gen * secrets.randbelow(gen.order)
       p2 = gen * secrets.randbelow(gen.order)

       t = monotonic_ns()
       p1 + p2
       T += monotonic_ns()-t

    lib,bench = "ecc","point_add"
    return f"{lib},{bench},{T/reps}\n"

def ecpy_point_double(reps=1000):
    cv = ecpy.curves.Curve.get_curve('secp256k1')
    gen = cv.generator
    T = 0
    for _ in range(reps):
       p1 = secrets.randbelow(cv.order) * gen

       t = monotonic_ns()
       p1*2
       T += monotonic_ns()-t

    lib,bench = "ecpy","point_double"
    return f"{lib},{bench},{T/reps}\n"

def ecc_point_double(reps=1000):
    cv, gen = ecc.load_space('secp256k1')
    T = 0
    for _ in range(reps):
       p1 = gen * secrets.randbelow(gen.order)

       t = monotonic_ns()
       p1*2
       T += monotonic_ns()-t

    lib,bench = "ecc","point_double"
    return f"{lib},{bench},{T/reps}\n"

def ecpy_scalar_mult(reps=1000):
    cv = ecpy.curves.Curve.get_curve('secp256k1')
    gen = cv.generator
    T = 0
    for _ in range(reps):
       p1 = secrets.randbelow(cv.order) * gen
       s  = secrets.randbelow(cv.order)

       t = monotonic_ns()
       p1*s
       T += monotonic_ns()-t

    lib,bench = "ecpy","scalar_mult"
    return f"{lib},{bench},{T/reps}\n"

def ecc_scalar_mult(reps=1000):
    cv, gen = ecc.load_space('secp256k1')
    T = 0
    for _ in range(reps):
       p1 = gen * secrets.randbelow(gen.order)
       s  =       secrets.randbelow(gen.order)

       t = monotonic_ns()
       p1*s
       T += monotonic_ns()-t

    lib,bench = "ecc","scalar_mult"
    return f"{lib},{bench},{T/reps}\n"

def ecpy_find_y(reps=1000):
    cv = ecpy.curves.Curve.get_curve('secp256k1')
    T = 0
    for _ in range(reps):
       x = secrets.randbelow(cv.field)
       t = monotonic_ns()
       cv.y_recover(x)
       T += monotonic_ns()-t

    lib,bench = "ecpy","find_y"
    return f"{lib},{bench},{T/reps}\n"

def ecc_find_y(reps=1000):
    cv, gen = ecc.load_space('secp256k1')
    T = 0
    for _ in range(reps):
       x = secrets.randbelow(cv.p)
       t = monotonic_ns()
       cv.find_y(x)
       T += monotonic_ns()-t

    lib,bench = "ecc","find_y"
    return f"{lib},{bench},{T/reps}\n"

def ecpy_find_y_existing(reps=1000):
    cv = ecpy.curves.Curve.get_curve('secp256k1')
    T = 0
    i = 0
    while i < reps:
       x = secrets.randbelow(cv.field)
       t = monotonic_ns()
       y=cv.y_recover(x)
       t2 = monotonic_ns()-t
       if y is not None:
           T += t2
           i += 1

    lib,bench = "ecpy","find_y_existing"
    return f"{lib},{bench},{T/reps}\n"

def ecc_find_y_existing(reps=1000):
    cv, gen = ecc.load_space('secp256k1')
    T = 0
    i = 0
    while i < reps:
       x = secrets.randbelow(cv.p)
       t = monotonic_ns()
       y = cv.find_y(x)
       t2 = monotonic_ns()-t
       if y is not None:
           T += t2
           i += 1

    lib,bench = "ecc","find_y_existing"
    return f"{lib},{bench},{T/reps}\n"