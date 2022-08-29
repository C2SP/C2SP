from hashlib import sha256
from math import log2, floor

# Returns the largest power of 2 smaller than n
def prev_power_of_two(n):
    # This is the largest power of 2 no greater than n-1, i.e., k <= n-1, i.e., largest power of 2
    # smaller than n.
    return 2 ** floor(log2(n-1))

# RFC 6962 §2.1 - Merkle Hash Trees
# Base def:
#     MTH({d(0)}) = SHA-256(0x00 || d(0))
# Recursive defs: For m < n, let k be the largest power of two smaller than n.
#     MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
def mth(d):
    n = len(d)
    if n == 1:
        return sha256(b"\x00" + d[0]).digest()
    else:
        k = prev_power_of_two(n)
        return sha256(b"\x01" + mth(d[0:k]) + mth(d[k:n])).digest()

# RFC 6962 §2.1.1 - Merkle Audit Paths
# Base def:
#     PATH(0, {d(0)}) = {}
# Recursive defs: For m < n, let k be the largest power of two smaller than n.
#     PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])      if m < k
#     PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k])  if m >= k
def path(m, d):
    n = len(d)
    if n == 1:
        return b""
    else:
        k = prev_power_of_two(n)
        if m < k:
            return path(m, d[0:k]) + mth(d[k:n])
        else:
            return path(m - k, d[k:n]) + mth(d[0:k])

# RFC 6962 §2.1.2 - Merkle Consistency Proofs
# Base defs: For 0 < m < n,
#     PROOF(m, D[n]) = SUBPROOF(m, D[n], true)
#     SUBPROOF(m, D[m], true) = {}
#     SUBPROOF(m, D[m], false) = {MTH(D[m])}
# Recursive defs: For m < n, let k be the largest power of two smaller than n.
#     SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])          if m <= k
#     SUBPROOF(m, D[n], b) = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])  if m > k
def proof(m, d):
    def subproof(m, d, b):
        n = len(d)
        if m == n:
            if b:
                return b""
            else:
                return mth(d)
        else:
            k = prev_power_of_two(n)
            if m <= k:
                return subproof(m, d[0:k], b) + mth(d[k:n])
            else:
                return subproof(m - k, d[k:n], False) + mth(d[0:k])

    return subproof(m, d, True)

# This spec
# Base def:
#     BPATH({0}, {d(0)}) = {}
# Recursive defs: For n > 1, let k be the largest power of two smaller than n. Let l be the largest
# integer such that m(i) < k for all i < l.
#     BPATH(M[r], D[n]) = BPATH(M[r], D[0:k]) : MTH(D[k:n])                  if l == r
#     BPATH(M[r], D[n]) = BPATH(M[r] - k, D[k:n]) : MTH(D[0:k])              if l == 0:
#     BPATH(M[r], D[n]) = BPATH(M[0:l], D[0:k]) : BPATH(M[l:r] - k, D[k:n])  else
def bpath(m, d):
    n = len(d)
    r = len(m)

    if n == 1:
        return b""
    else:
        k = prev_power_of_two(n)
        l = 0
        while l < r and m[l] < k:
            l += 1

        if l == r:
            return bpath(m, d[0:k]) + mth(d[k:n])
        elif l == 0:
            return bpath([mi - k for mi in m], d[k:n]) + mth(d[0:k])
        else:
            return bpath(m[0:l], d[0:k]) + bpath([mi - k for mi in m[l:r]], d[k:n])


#
# Generate test vectors
#
if __name__ == "__main__":
    from random import randbytes, randrange, sample, seed as randseed
    import json

    # Make the RNG deterministic
    randseed(b"C2SP Batch Merkle Audit Path")

    max_num_leaves = 64

    # Make a tree `D[n]` where `d(i)` is the two-byte big-endian representation of the integer `i`.
    def gen_leaves(n):
        return [i.to_bytes(2, byteorder="big") for i in range(n)]

    # Make 10 test vectors for MTH
    mth_test_vecs = []
    for _ in range(10):
        num_leaves = randrange(1, max_num_leaves)
        leaves = gen_leaves(num_leaves)
        h = mth(leaves)

        mth_test_vecs.append({
            "num_leaves": num_leaves,
            "tree_hash": h.hex(),
        })

    # Make 100 test vectors for PATH
    inclusion_test_vecs = []
    for _ in range(100):
        num_leaves = randrange(1, max_num_leaves+1)
        leaves = gen_leaves(num_leaves)
        idx = randrange(num_leaves)

        inclusion_proof = path(idx, leaves)
        inclusion_test_vecs.append({
            "num_leaves": num_leaves,
            "idx": idx,
            "inclusion_proof": inclusion_proof.hex(),
        })

        # Check that PATH == BPATH for single-idx proofs
        assert(inclusion_proof == bpath([idx], leaves))

    # Make 100 test vectors for BPATH using random subsets
    batch_inclusion_test_vecs = []
    for _ in range(100):
        num_leaves = randrange(1, max_num_leaves+1)
        leaves = gen_leaves(num_leaves)

        batch_size = randrange(1, num_leaves+1)

        idxs = sample(range(num_leaves), batch_size)
        idxs.sort()

        batch_inclusion_proof = bpath(idxs, leaves)
        batch_inclusion_test_vecs.append({
            "num_leaves": num_leaves,
            "idxs": idxs,
            "batch_inclusion_proof": batch_inclusion_proof.hex(),
        })

    # Make 100 test vectors for BPATH using random continguous slices
    for _ in range(100):
        num_leaves = randrange(1, max_num_leaves+1)
        leaves = gen_leaves(num_leaves)
        batch_size = randrange(1, num_leaves+1)

        start_idx = randrange(num_leaves)
        max_end_idx = min(start_idx + batch_size, num_leaves) + 1;
        end_idx = randrange(start_idx + 1, max_end_idx);

        idxs = list(range(start_idx, end_idx))
        idxs.sort()

        batch_inclusion_proof = bpath(idxs, leaves)
        batch_inclusion_test_vecs.append({
            "num_leaves": num_leaves,
            "idxs": idxs,
            "batch_inclusion_proof": batch_inclusion_proof.hex(),
        })

    # Make 100 test vectors for PROOF
    consistency_test_vecs = []
    for _ in range(100):
        num_leaves = randrange(2, max_num_leaves+1)
        leaves = gen_leaves(num_leaves)
        subtree_size = randrange(1, num_leaves)

        consistency_proof = proof(subtree_size, leaves)
        consistency_test_vecs.append({
            "num_leaves": num_leaves,
            "subtree_size": subtree_size,
            "consistency_proof": consistency_proof.hex(),
        })

    with open("mth.json", "w+") as f:
        json.dump(mth_test_vecs, f, indent=2)
    with open("path.json", "w+") as f:
        json.dump(inclusion_test_vecs, f, indent=2)
    with open("bpath.json", "w+") as f:
        json.dump(batch_inclusion_test_vecs, f, indent=2)
    with open("consistency.json", "w+") as f:
        json.dump(consistency_test_vecs, f, indent=2)

    # TODO: Make test vectors that should not verify
    # TODO: Make test vectors for other hash functions
    # TODO: Decide whether to make normative verification section. If so, make should_panic test
    # vectors as well

    '''
    #
    # Make test vectors that should cause a panic
    #

    # idx < num_leaves for PATH. We violate this here:
    num_leaves = randrange(1, max_num_leaves+1)
    idx = num_leaves
    inclusion_panic_test_vec = {
        "num_leaves": num_leaves,
        "idx": idx,
    }
    print(f"{inclusion_panic_test_vec=}")

    # idx[i] < num_leaves for all i in BPATH. We violate this by setting 1 idx out of range
    num_leaves = randrange(1, max_num_leaves+1)
    idxs = sample(range(num_leaves), batch_size)
    idxs[randrange(batch_size)] = num_leaves
    idxs.sort()
    batch_inclusion_panic_test_vec = {
        "num_leaves": num_leaves,
        "idxs": idxs,
    }
    print(f"{batch_inclusion_panic_test_vec=}")

    # subtree_size < num_leaves for PROOF. We violate this here:
    num_leaves = randrange(1, max_num_leaves+1)
    subtree_size = num_leaves
    proof_panic_test_vec_1 = {
        "num_leaves": num_leaves,
        "subtree_size": subtree_size,
    }
    print(f"{proof_panic_test_vec_1=}")

    # subtree_size > 0 for PROOF. We violate this here:
    num_leaves = randrange(1, max_num_leaves+1)
    subtree_size = 0
    proof_panic_test_vec_2 = {
        "num_leaves": num_leaves,
        "subtree_size": subtree_size,
    }
    print(f"{proof_panic_test_vec_2=}")
    '''
