# Poseidon sponge construction

- Version: 0.0.0
- Maintainer: Jack Grigg

## Introduction

This document specifies the Poseidon sponge construction, a duplex sponge [[BDPV2011]]
instantiated with the [Poseidon permutation]. It also specifies several instantiations of
the sponge for use in various hashing domains.

[BDPV2011]: https://keccak.team/files/SpongeDuplex.pdf
[Poseidon permutation]: ./poseidon-permutation.md

## Notation and conventions

- `[a, b)` means the sequence of integers from `a` inclusive to `b` exclusive.
- `[x; N]` means an array of length `N` where every entry is filled with `x`.
- `y[i]` means the element of the array `y` at index `i`.
- `len(y)` means the length of the array `y`. For example, `len([x; N]) == N`.

## Duplex sponge

The duplex sponge `PoseidonSponge` is built around `PoseidonPermutation`, a permutation of
width `T`, which encapsulates the specific Poseidon parameters for the sponge. It has a
parameter `RATE`, the number of input field elements processed by each invocation of the
permutation, which is at most `T - 1`. The value `C = T - RATE` is called the capacity.

> TODO: Describe how the permutation instance and the rate relate to each other and to the
> desired security parameter `M`.

`PoseidonSponge` has several internal properties:
- An internal state of `T` field elements.
- A mode variable that is either `absorbing` or `squeezing`.
- A cache of field elements corresponding to the current mode.
- A duplex padding function that is applied to input elements prior to incorporating them
  into the sponge state.

The only operations exposed by the sponge are:
- `PoseidonSponge.Initialize`, which prepares a new sponge.
- `PoseidonSponge.Absorb`, which takes a single field element into the sponge.
- `PoseidonSponge.Squeeze`, which produces a single field element derived from all prior
  `Absorb` and `Squeeze` operations on the sponge, as well as the initialization values.

`PoseidonSponge.Initialize` must only be called once per sponge, and must be called first.
After that, `PoseidonSponge.Absorb` and `PoseidonSponge.Squeeze` may be called repeatedly
and in any order.

The sponge has an internal state of width `T`, divided into two sections:
- Field elements at indices `[0, RATE)` form the "rate" portion of the sponge.
- Field elements at indices `[RATE, T)` (the last `C` field elements of the state) form
  the capacity portion of the sponge. These elements are never directly affected by the
  input field elements, and are never output during the squeezing phase.

> Note: Both the duplex sponge construction from [[BDPV2011]], and the plain sponge
> construction it is derived from [[BDPV2007]], use an internal state with the form
> `rate || capacity`. Section 2.1 of the Poseidon paper matched this internal state form
> when specifying the Poseidon sponge. However, Appendix I of the Poseidon paper (which
> describes a particular use of the Poseidon sponge within Merkle tree hashing) used
> `capacity || rate` instead, and at least one instance of Poseidon Merkle tree hashing
> matching Appendix I was deployed into production before this inconsistency was noticed.
>
> TODO: Examine all open-source production instances of Poseidon to figure out how far
> this inconsistency propagated, and what other variants might currently exist.

[BDPV2007]: https://keccak.team/files/SpongeFunctions.pdf

### Initialization

`PoseidonSponge.Initialize` takes as input a `PoseidonPermutation`, a field element
`domain_iv` that is used for domain separation, and a `duplex_padding` function. It
proceeds as follows:

1. Initialize the sponge state. The first element of the capacity portion is set to
   `domain_iv`, while the remaining capacity elements, and all of the rate elements, are
   initialized to zero.
   ```
   state = [0; T]
   state[RATE] = domain_iv
   ```

2. Return the new sponge:
   ```
   PoseidonSponge(
     PoseidonPermutation,
     state,
     mode = absorbing,
     cache = [],
     duplex_padding,
   )
   ```

> TODO: Should `RATE` be passed directly to `PoseidonSponge.Initialize` instead of being
> an implicit parameter?

### Internal helper functions

`ZeroExtend` is a function that takes an input of between zero and `RATE` field elements.
It appends the array `[0; RATE - len(input)]` and returns the result.

`PoseidonSponge.PerformDuplex` takes an input of between zero and `RATE` field elements.
It proceeds as follows:

1. Apply the domain's padding function to the input, resulting in a padded input of `RATE`
   field elements.

2. Add the padded input element-wise to the rate portion of `state`:
   ```
   for i in [0, RATE):
       state[i] += padded_input[i]
   ```

3. Call `PoseidonPermutation(state)`.

4. Return the first `RATE` field elements of `state` as output.

### Absorb

`PoseidonSponge.Absorb` takes a single field element `input`, and proceeds as follows:

- If `mode == absorbing`:
  - If `len(cache) == RATE`:
    1. Call `PoseidonSponge.PerformDuplex(cache)`, and drop the result.
    2. Set `cache` to `[input; 1]`.

  - Else (there is room in `cache`):
    1. Append `input` to the end of `cache`.

- Else (`mode == squeezing`):
  1. Drop any remaining cached output elements (by setting `cache` to `[]`).
  2. Set `mode` to `absorbing`.
  3. Set `cache` to `[input; 1]`.

### Squeeze

`PoseidonSponge.Squeeze` proceeds as follows:

1. If `mode == squeezing` and `len(cache) == 0`:
   1. Set `mode` to `absorbing`.
   2. Set `cache` to `[]` (this is already the case, but for clarity this means there are
      no elements to be absorbed).

2. If `mode == absorbing`:
   1. `new_output_elements = PoseidonSponge.PerformDuplex(cache)`.
   2. Set `mode` to `squeezing`.
   3. Set `cache` to `new_output_elements`.

3. Remove the first element from `cache` and return it.

## Hash functions

### Hash function with fixed-length input

`PoseidonHash.ConstantLength` takes as input:

- A `PoseidonPermutation` with the desired properties.
- `message`, an array of `msg_len` field elements (where `msg_len` is a fixed constant in
  some higher-level protocol).
- An output size `out_len`.

Hashing proceeds as follows:

```
sponge = PoseidonSponge.Initialize(
    PoseidonPermutation,
    (msg_len << 64) + (out_len - 1),
    ZeroExtend,
)

for i in [0, msg_len):
    sponge.Absorb(message[i])

output = [0; out_len]
for i in [0, out_len):
    output[i] = sponge.Squeeze()
return output
```

### Hash function with variable-length input

`PoseidonHash.VariableLength` takes as input:

- A `PoseidonPermutation` with the desired properties.
- `message`, a sequence of field elements of variable length.
- An output size `out_len`.

Hashing proceeds as follows:

```
sponge = PoseidonSponge.Initialize(
    PoseidonPermutation,
    (1 << 64) + (out_len - 1),
    ZeroExtend,
)

for i in [0, len(message)):
    sponge.Absorb(message[i])

# Domain-separate from fixed-length hash by terminating the message with a constant.
sponge.Absorb(1)

output = [0; out_len]
for i in [0, out_len):
    output[i] = sponge.Squeeze()
return output
```
