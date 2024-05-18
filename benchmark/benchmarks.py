import ecpy.curves
from ecc_imp import ecc
import ecpy
import secrets
from time import monotonic_ns

def ecpy_secp265k1_ecdsa_const_msg(msg_len=32, reps=1000):
    from ecpy.curves     import Curve
    from ecpy.keys       import ECPrivateKey
    from ecpy.ecdsa      import ECDSA

    msg    = secrets.token_bytes(msg_len)
    cv     = Curve.get_curve('secp256k1')
    signer = ECDSA()
    sg_times = []
    vr_times = []

    for _ in range(reps):
        pv_key = ECPrivateKey(secrets.randbelow(cv.order),cv)
        pu_key = pv_key.get_public_key()
        
        t = monotonic_ns()
        sig = signer.sign(msg,pv_key)
        sg_times.append(monotonic_ns()-t)

        t = monotonic_ns()
        signer.verify(msg,sig,pu_key)
        vr_times.append(monotonic_ns()-t)

    print(f"Average sign time: {sum(sg_times)/reps} ns")
    print(f"Average verify time: {sum(vr_times)/reps} ns")

def ecc_secp256k1_ecdsa_const_msg(msg_len=32, reps=1000):

    msg = secrets.token_bytes(msg_len)
    cv, gen = ecc.load_space('secp256k1')
    sg_times = []
    vr_times = []

    for _ in range(reps):
        priv =    secrets.randbelow(gen.order)
        key =     ecc.ECKey(cv, gen, priv_key=priv).generate()

        t = monotonic_ns()
        sig = ecc.ecdsa_sign(int.from_bytes(msg, 'big'), key)
        sg_times.append(monotonic_ns()-t)
        t = monotonic_ns()
        ecc.ecdsa_verify(int.from_bytes(msg, 'big'), sig, key)
        vr_times.append(monotonic_ns()-t)

    print(f"Average sign time: {sum(sg_times)/reps} ns")
    print(f"Average verify time: {sum(vr_times)/reps} ns")

def ecpy_secp265k1_ecdsa_var_msg(msg_len=32, reps=1000):
    from ecpy.curves     import Curve
    from ecpy.keys       import ECPrivateKey
    from ecpy.ecdsa      import ECDSA

    cv     = Curve.get_curve('secp256k1')
    signer = ECDSA()
    sg_times = []
    vr_times = []

    for _ in range(reps):
        pv_key = ECPrivateKey(secrets.randbelow(cv.order),cv)
        pu_key = pv_key.get_public_key()
        msg    = secrets.token_bytes(msg_len)
        
        t = monotonic_ns()
        sig = signer.sign(msg,pv_key)
        sg_times.append(monotonic_ns()-t)

        t = monotonic_ns()
        signer.verify(msg,sig,pu_key)
        vr_times.append(monotonic_ns()-t)

    print(f"Average sign time: {sum(sg_times)/reps} ns")
    print(f"Average verify time: {sum(vr_times)/reps} ns")

def ecc_secp256k1_ecdsa_var_msg(msg_len=32, reps=1000):
    
        cv, gen = ecc.load_space('secp256k1')
        sg_times = []
        vr_times = []
    
        for _ in range(reps):
            priv =    secrets.randbelow(gen.order)
            key =     ecc.ECKey(cv, gen, priv_key=priv).generate()
            msg =     secrets.token_bytes(msg_len)
    
            t = monotonic_ns()
            sig = ecc.ecdsa_sign(int.from_bytes(msg, 'big'), key)
            sg_times.append(monotonic_ns()-t)
            t = monotonic_ns()
            ecc.ecdsa_verify(int.from_bytes(msg, 'big'), sig, key)
            vr_times.append(monotonic_ns()-t)
    
        print(f"Average sign time: {sum(sg_times)/reps} ns")
        print(f"Average verify time: {sum(vr_times)/reps} ns")

def ecpy_secp265k1_ecdsa_const_key(msg_len=32, reps=1000):
    from ecpy.curves     import Curve
    from ecpy.keys       import ECPrivateKey
    from ecpy.ecdsa      import ECDSA

    cv     = Curve.get_curve('secp256k1')
    signer = ECDSA()
    sg_times = []
    vr_times = []

    pv_key = ECPrivateKey(secrets.randbelow(cv.order),cv)
    pu_key = pv_key.get_public_key()

    for _ in range(reps):
        msg = secrets.token_bytes(msg_len)
        t = monotonic_ns()
        sig = signer.sign(msg,pv_key)
        sg_times.append(monotonic_ns()-t)

        t = monotonic_ns()
        signer.verify(msg,sig,pu_key)
        vr_times.append(monotonic_ns()-t)

    print(f"Average sign time: {sum(sg_times)/reps} ns")
    print(f"Average verify time: {sum(vr_times)/reps} ns")

def ecc_secp256k1_ecdsa_const_key(msg_len=32, reps=1000):
    
        cv, gen = ecc.load_space('secp256k1')
        sg_times = []
        vr_times = []
    
        priv =    secrets.randbelow(gen.order)
        key =     ecc.ECKey(cv, gen, priv_key=priv).generate()
    
        for _ in range(reps):
            msg = secrets.token_bytes(msg_len)
            t = monotonic_ns()
            sig = ecc.ecdsa_sign(int.from_bytes(msg, 'big'), key)
            sg_times.append(monotonic_ns()-t)
            t = monotonic_ns()
            ecc.ecdsa_verify(int.from_bytes(msg, 'big'), sig, key)
            vr_times.append(monotonic_ns()-t)
    
        print(f"Average sign time: {sum(sg_times)/reps} ns")
        print(f"Average verify time: {sum(vr_times)/reps} ns")

def ecpy_secp256k1_point_add():
     pass

def ecc_secp256k1_point_add():
     cv, gen = ecc.load_space('secp256k1')