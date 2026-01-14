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

    def add_vector(bits, seed: str | list[str], check):
        if isinstance(seed, str):
            seed = [seed]
        seeds = [bytes.fromhex(s) for s in seed]
        cheapest_vector, cheapest_vector_rejections = None, 0
        for s in seeds:
            keygen_result = det_rsa_keygen(s, bits)
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
            rejections = sum(p + q for p, q in keygen_result.rejected_candidates)
            print(f"Bits: {bits}", file=sys.stderr)
            print(f"Seed: {s.hex()}", file=sys.stderr)
            print(f"Rejections (p, q): {keygen_result.rejected_candidates}", file=sys.stderr)
            print(f"Total rejections: {rejections}", file=sys.stderr)
            print(f"Ratio lengths: {keygen_result.ratio_lengths}", file=sys.stderr)
            print(f"Totient GCDs: {keygen_result.totient_gcds}", file=sys.stderr)
            print(f"", file=sys.stderr)
            if not check(keygen_result):
                raise ValueError("result does not meet check criteria")
            if keygen_result.key.private_numbers().public_numbers.n.bit_length() != bits:
                raise ValueError("generated key has incorrect bit length")
            if cheapest_vector is None or rejections < cheapest_vector_rejections:
                cheapest_vector = {
                    "bits": bits,
                    "seed": base64.b64encode(s).decode(),
                    "private_key_pkcs8": base64.b64encode(pkcs8).decode(),
                }
                cheapest_vector_rejections = rejections
        vectors.append(cheapest_vector)

    pair_rejections = lambda keygen_result, n: len(keygen_result.rejected_candidates) - 1 == n

    # Various bit sizes with low but not zero prime rejections
    not_zero_rejections = lambda keygen_result: (
        all(p != 0 and q != 0 for p, q in keygen_result.rejected_candidates)
        and pair_rejections(keygen_result, 0)
    )
    add_vector(2048, "5e5d94fba9a4686328b2af3d7a92736e", not_zero_rejections)
    add_vector(2064, "95e743c1d5bc006e16dc1cb719bb9af0", not_zero_rejections)
    add_vector(3072, "4a640716c878976a853a4efa5e70bf96", not_zero_rejections)
    add_vector(4096, "88b0c77cd04e7c741292220989db43c4", not_zero_rejections)
    add_vector(8192, "e5effe83a577eb84be466a7f14e0bb16", not_zero_rejections)

    # Various seed size with low but not zero rejections
    add_vector(2048, "4e48cac10c490afce06dfa51de74ca05fd1c1e0493", not_zero_rejections)
    add_vector(2048, "53b6b04aca33a9966f643fae6391fc46701ddc3b4b5ae096", not_zero_rejections)
    s = "0c6e23c79b3a55b81e8d0ae39408d4a5573a40801c5720433dea1821c64f6bc0cbb32ea2"
    add_vector(2048, s, not_zero_rejections)
    s = "53b86d5f4e3bdc5440c7a4a237a66ffa46cae6580666533b697ecee53591ee6ced4bf4d5ba2154fc759f19334db57a8f"
    add_vector(2048, s, not_zero_rejections)

    # Immediate success on prime candidate p
    immediate_p = lambda keygen_result: (
        keygen_result.rejected_candidates[0][0] == 0
        and keygen_result.rejected_candidates[0][1] != 0
        and pair_rejections(keygen_result, 0)
    )
    add_vector(2048, "3157e37c9674ccf0db9c00f8837c1a84", immediate_p)

    # Immediate success on prime candidate q
    immediate_q = lambda keygen_result: (
        keygen_result.rejected_candidates[0][1] == 0
        and keygen_result.rejected_candidates[0][0] != 0
        and pair_rejections(keygen_result, 0)
    )
    add_vector(2048, "854ccac10c490afce06dfa51de74ca05fd1c1e0493", immediate_q)

    # Immediate success on both prime candidates p and q
    immediate_both = lambda keygen_result: (
        keygen_result.rejected_candidates[0][0] == 0
        and keygen_result.rejected_candidates[0][1] == 0
        and pair_rejections(keygen_result, 0)
    )
    add_vector(2048, "047894fba9a4686328b2af3d7a92736e", immediate_both)

    # d is shorter than N across a 64-bit boundary
    short_d = lambda keygen_result: (
        pair_rejections(keygen_result, 0)
        and keygen_result.key.private_numbers().d.bit_length()
        <= (keygen_result.key.private_numbers().public_numbers.n.bit_length() // 64) * 64
    )
    add_vector(2064, "0009b47d1f61690278b450d288042771", short_d)

    # Rejected due to P-1 divisible by e
    e_divides_p_minus_1 = lambda keygen_result: (
        pair_rejections(keygen_result, 1)
        and [gcd != 1 for gcd in keygen_result.totient_gcds[0]] == [True, False]
    )
    add_vector(2048, "28f4db691db27fe94f86bf067c2cbcf7", e_divides_p_minus_1)

    # Rejected due to Q-1 divisible by e
    e_divides_q_minus_1 = lambda keygen_result: (
        pair_rejections(keygen_result, 1)
        and [gcd != 1 for gcd in keygen_result.totient_gcds[0]] == [False, True]
    )
    add_vector(2048, "f4d81c0bfaab20dff35e2e8a1c8a7e9c", e_divides_q_minus_1)

    # Rejected due to both P-1 and Q-1 divisible by e
    e_divides_both_minus_1 = lambda keygen_result: (
        pair_rejections(keygen_result, 1)
        and [gcd != 1 for gcd in keygen_result.totient_gcds[0]] == [True, True]
    )
    add_vector(2048, "922d728a940eb630327a43c83a025a21", e_divides_both_minus_1)

    # Rejected twice due to P-1/Q-1 divisible by e
    e_divides_either_minus_1_twice = lambda keygen_result: (
        pair_rejections(keygen_result, 2)
        and sum(1 for gcd in keygen_result.totient_gcds[0] if gcd != 1) == 1
        and sum(1 for gcd in keygen_result.totient_gcds[1] if gcd != 1) == 1
    )
    add_vector(
        2048,
        [
            "3ac157fa8cf23c3da63f431e10a79724",
            "25fa373deb61ed27f0e070fb1abace6e",
            "93a3cbd058a8264ea1aced45ab328c91",
            "59c55f82fd340d89321978bb5a3c970b",
            "6054832c6949e11ba6ac20795c29deb9",
            "9549a8515cb1ebcc76124d8bc3821a2f",
            "56aa66de42f0e0b0a096644c44ec9f69",
            "061f65a3ba6ef9952145827e78eeeccf",
            "0a720a90a9d637c04e7aadae80ced132",
            "4dac53b0f5339d88c86689868d683ea9",
        ],
        e_divides_either_minus_1_twice,
    )

    # 2^30 <= gcd(p-1,q-1) < 2^31, not rejected
    ratio_bitlen_31 = lambda keygen_result: (
        pair_rejections(keygen_result, 0) and keygen_result.ratio_lengths[0] == 31
    )
    add_vector(
        2048,
        [
            "c3d0375e7cef9c92a72849f5856ac28a",
            "42959cc64df568ce8b022de6e1103819",
            "ccba7e74b19a056d4ba90183e7a56f58",
            "a535687a2ec5f1279944a3f4815e0f20",
            "288684c117605393ce0236e233538f23",
            "18e7e75892868218b02992b0d9c949a9",
            "4d2e0dc1fd97241f2447707137d4e3d6",
            "a535687a2ec5f1279944a3f4815e0f20",
            "ebb1ef958dce2016868255bfc5a16c28",
            "30c1eed294a21b5243d8943b8bfd2ae3",
            "38045d4e6a8af7431eadd3a29c3c42a0",
            "86d683ca429693133974213ac4eaa788",
        ],
        ratio_bitlen_31,
    )

    # 2^31 <= gcd(p-1,q-1) < 2^32, not rejected
    ratio_bitlen_32 = lambda keygen_result: (
        pair_rejections(keygen_result, 0) and keygen_result.ratio_lengths[0] == 32
    )
    add_vector(
        2048,
        [
            "10dcdbfc8b0a161ad38152bfa12fd637",
            "8764d391ed53c250a11a1d635f3740b8",
            "3685289ca75e6e9e1089bc864d5880d1",
            "116c0b59528250d49782b96bfe4636b2",
            "cce06fcd8984c864c22f36397c814a82",
            "636095a55f61b977b516a3af812785b0",
        ],
        ratio_bitlen_32,
    )

    # 2^32 <= gcd(p-1,q-1) < 2^33, rejected
    ratio_bitlen_33 = lambda keygen_result: (
        pair_rejections(keygen_result, 1) and keygen_result.ratio_lengths[0] == 33
    )
    add_vector(
        2048,
        [
            "b38a65c4cfe3810cd474248178d8a119",
            "c8cd81fe6e1851094e9500a930dfbbca",
        ],
        ratio_bitlen_33,
    )

    # 2^33 <= gcd(p-1,q-1) < 2^34, rejected
    ratio_bitlen_34 = lambda keygen_result: (
        pair_rejections(keygen_result, 1) and keygen_result.ratio_lengths[0] == 34
    )
    add_vector(2048, "e0ca825f59515128106ef931c39fc8d5", ratio_bitlen_34)

    print(json.dumps(vectors, indent=4))


if __name__ == "__main__":
    main()
