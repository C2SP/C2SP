import sys
import json
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def det_ecdsa_keygen(seed: bytes, curve: ec.EllipticCurve) -> ec.EllipticCurvePrivateKey:
    if len(seed) < 16:
        raise ValueError("seed must be at least 16 bytes long")

    # Curve parameters
    personalization = {
        "secp224r1": b"det ECDSA key gen P-224",
        "secp256r1": b"det ECDSA key gen P-256",
        "secp384r1": b"det ECDSA key gen P-384",
        "secp521r1": b"det ECDSA key gen P-521",
    }

    if curve.name not in personalization:
        raise ValueError(f"Unsupported curve: {curve.name}")

    # HMAC_DRBG instantiation
    K = b"\x00" * 32
    V = b"\x01" * 32

    # Step 4
    K = hmac.new(K, V + b"\x00" + seed + personalization[curve.name], hashlib.sha256).digest()

    # Step 5
    V = hmac.new(K, V, hashlib.sha256).digest()

    # Step 6
    K = hmac.new(K, V + b"\x01" + seed + personalization[curve.name], hashlib.sha256).digest()

    # Step 7
    V = hmac.new(K, V, hashlib.sha256).digest()

    def generate_candidate():
        nonlocal K, V
        n_bytes = (curve.key_size + 7) // 8

        # Steps 8-9: Generate temp
        temp = b""
        while len(temp) < n_bytes:
            V = hmac.new(K, V, hashlib.sha256).digest()
            temp += V

        # Step 10: bits2int
        d = int.from_bytes(temp[:n_bytes], "big")

        if curve.name == "secp521r1":
            # For P-521, right-shift by 7 bits
            d >>= 7

        return d

    # Generate first candidate
    d = generate_candidate()

    # Step 11: Retry for P-256 if d >= n
    if curve.name == "secp256r1" and d >= curve.group_order:
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()
        d = generate_candidate()

    # Step 12: Check validity (cryptographically negligible probability)
    if d == 0 or d >= curve.group_order:
        raise RuntimeError("generated invalid private key")

    # Step 13-14: Generate public key
    return ec.derive_private_key(d, curve)


def main():
    vectors = []

    def add_vector(curve, seed):
        key = det_ecdsa_keygen(seed, curve)
        pkcs8 = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        print(
            f"Curve: {curve.name}\nSeed: {seed.hex()}\nPrivate Key:\n{pem.decode()}\n",
            file=sys.stderr,
        )
        vectors.append(
            {
                "curve": curve.name,
                "seed": base64.b64encode(seed).decode(),
                "private_key_pkcs8": base64.b64encode(pkcs8).decode(),
            }
        )

    for curve in [ec.SECP224R1(), ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]:
        for bits in [128, 168, 192, 288, 384]:
            seed = b"\x42" * (bits // 8)
            add_vector(curve, seed)
        if curve.name == "secp256r1":
            seed = bytes.fromhex("b432f9be30890480298218510559aed7")
            add_vector(curve, seed)

    print(json.dumps(vectors, indent=4))


if __name__ == "__main__":
    main()
