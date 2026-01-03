import sys
import json
import base64
import hashlib
import hmac
import math
from dataclasses import dataclass
from sympy import isprime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


@dataclass
class KeygenResult:
    key: rsa.RSAPrivateKey
    rejected_candidates: list[tuple[int, int]]
    ratio_lengths: list[int]
    totient_gcds: list[tuple[int, int]]


def det_rsa_keygen(seed: bytes, bits: int) -> KeygenResult:
    if len(seed) < 16:
        raise ValueError("seed must be at least 16 bytes long")

    if bits < 2048 or bits > 65520 or bits % 16 != 0:
        raise ValueError("key size must be at least 2048 bits and a multiple of 16")

    # Step 1
    personalization = b"det RSA key gen" + bits.to_bytes(2, "big")

    # HMAC_DRBG instantiation
    K = b"\x00" * 32
    V = b"\x01" * 32

    # Step 4
    K = hmac.new(K, V + b"\x00" + seed + personalization, hashlib.sha256).digest()

    # Step 5
    V = hmac.new(K, V, hashlib.sha256).digest()

    # Step 6
    K = hmac.new(K, V + b"\x01" + seed + personalization, hashlib.sha256).digest()

    # Step 7
    V = hmac.new(K, V, hashlib.sha256).digest()

    first_candidate = True

    def generate_candidate():
        nonlocal K, V, first_candidate

        if not first_candidate:
            # Step {13,20,23}.1
            K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
            # Step {13,20,23}.2
            V = hmac.new(K, V, hashlib.sha256).digest()
        else:
            first_candidate = False

        # Steps 8-9
        temp = bytearray()
        while len(temp) < bits // 16:
            V = hmac.new(K, V, hashlib.sha256).digest()
            temp += V

        # Step 10
        temp[0] |= 0b1100_0000

        # Step 11
        temp[bits // 16 - 1] |= 0b0000_0111

        # Step 12
        return int.from_bytes(temp[: bits // 16], "big")

    rejected_candidates = []
    ratio_lengths = []
    totient_gcds = []

    while True:

        # Steps 13-14
        p_rejections = 0
        while True:
            p = generate_candidate()
            if isprime(p):
                break
            p_rejections += 1

        # Steps 15-18
        q_rejections = 0
        while True:
            q = generate_candidate()
            if isprime(q):
                break
            q_rejections += 1

        rejected_candidates.append((p_rejections, q_rejections))

        # Step 19
        ratio = math.gcd(p - 1, q - 1)

        # Step 20
        ratio_lengths.append(ratio.bit_length())
        if ratio >= 2**32:
            continue

        # Step 21
        λ = (p - 1) * (q - 1) // ratio

        # Step 22
        e = 65537

        # Step 23
        totient_gcds.append((math.gcd(e, p - 1), math.gcd(e, q - 1)))
        try:
            d = pow(e, -1, λ)
        except ValueError:
            continue

        # Step 25
        n = p * q

        if rsa.rsa_recover_private_exponent(e, p, q) != d:
            raise RuntimeError("Internal error: recovered private exponent mismatch")
        dmp1 = rsa.rsa_crt_dmp1(d, p)
        dmq1 = rsa.rsa_crt_dmq1(d, q)
        iqmp = rsa.rsa_crt_iqmp(p, q)
        key = rsa.RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=dmp1,
            dmq1=dmq1,
            iqmp=iqmp,
            public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
        ).private_key()

        return KeygenResult(
            key=key,
            rejected_candidates=rejected_candidates,
            ratio_lengths=ratio_lengths,
            totient_gcds=totient_gcds,
        )


def main():
    vectors = []

    def add_vector(bits, seed):
        keygen_result = det_rsa_keygen(seed, bits)
        pkcs8 = keygen_result.key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pem = keygen_result.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        print(f"Bits: {bits}", file=sys.stderr)
        print(f"Seed: {seed.hex()}", file=sys.stderr)
        print(f"Rejections (p, q): {keygen_result.rejected_candidates}", file=sys.stderr)
        print(f"Ratio lengths: {keygen_result.ratio_lengths}", file=sys.stderr)
        print(f"Totient GCDs: {keygen_result.totient_gcds}", file=sys.stderr)
        print(f"", file=sys.stderr)
        vectors.append(
            {
                "bits": bits,
                "seed": base64.b64encode(seed).decode(),
                "private_key_pkcs8": base64.b64encode(pkcs8).decode(),
            }
        )

    # Various bit sizes with low but not zero rejections
    add_vector(2048, bytes.fromhex("5e5d94fba9a4686328b2af3d7a92736e"))
    add_vector(2064, bytes.fromhex("95e743c1d5bc006e16dc1cb719bb9af0"))
    add_vector(3072, bytes.fromhex("4a640716c878976a853a4efa5e70bf96"))
    add_vector(4096, bytes.fromhex("88b0c77cd04e7c741292220989db43c4"))
    add_vector(8192, bytes.fromhex("e5effe83a577eb84be466a7f14e0bb16"))

    # Various seed size with low but not zero rejections
    add_vector(2048, bytes.fromhex("4e48cac10c490afce06dfa51de74ca05fd1c1e0493"))
    add_vector(2048, bytes.fromhex("53b6b04aca33a9966f643fae6391fc46701ddc3b4b5ae096"))
    s = "0c6e23c79b3a55b81e8d0ae39408d4a5573a40801c5720433dea1821c64f6bc0cbb32ea2"
    add_vector(2048, bytes.fromhex(s))
    s = "53b86d5f4e3bdc5440c7a4a237a66ffa46cae6580666533b697ecee53591ee6ced4bf4d5ba2154fc759f19334db57a8f"
    add_vector(2048, bytes.fromhex(s))

    # Immediate success on prime candidate p
    add_vector(2048, bytes.fromhex("3157e37c9674ccf0db9c00f8837c1a84"))
    # Immediate success on prime candidate q
    add_vector(2048, bytes.fromhex("854ccac10c490afce06dfa51de74ca05fd1c1e0493"))
    # Immediate success on both prime candidates p and q
    add_vector(2048, bytes.fromhex("047894fba9a4686328b2af3d7a92736e"))

    # d is shorter than N across a 64-bit boundary
    add_vector(2064, bytes.fromhex("0009b47d1f61690278b450d288042771"))

    # Rejected due to P-1 divisible by e
    add_vector(2048, bytes.fromhex("28f4db691db27fe94f86bf067c2cbcf7"))
    # Rejected due to Q-1 divisible by e
    add_vector(2048, bytes.fromhex("f4d81c0bfaab20dff35e2e8a1c8a7e9c"))
    # Rejected due to both P-1 and Q-1 divisible by e
    # TODO
    # Rejected twice due to P-1/Q-1 divisible by e
    # TODO

    # 2^31 < gcd(p-1,q-1) < 2^32, not rejected
    # TODO
    # 2^32 < gcd(p-1,q-1) < 2^32, rejected
    # TODO

    print(json.dumps(vectors, indent=4))


if __name__ == "__main__":
    main()
