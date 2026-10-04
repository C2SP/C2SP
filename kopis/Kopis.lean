import Mathlib.Data.ZMod.Basic
import Mathlib.LinearAlgebra.Matrix.Defs
import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Tactic.Ring
import Wychelean.Hashes.TurboSHAKE

/-! # The Kopis KEM, as specified in `kopis-spec.md`

Every function here corresponds to one in the specification, under the same name, and carries the
relevant spec text above it.

The pseudocode is transcribed as follows:

* `s[a..b]` is `slice s a (b - a)`, and `s[a..b] = t` is `s := s.setSlice a t`.
* `x[i] = v` is `x := x.set i v`, and `a || b` is `a ‖ b`.
* `r as R10` is `r.as_rn 10`, and `v as VecR10` is `v.as_vecn 10`.
* `r >> N` and `r << N` are `r >>> N` and `r <<< N`.
* A byte length written `n*256/8` is the same number as `32*n`; we use whichever form makes the
  types line up. -/

namespace Kopis

open Wychelean (Byte)
open scoped Wychelean.Notations

abbrev 𝔹 := Wychelean.ByteVec

/-- Lets `grind` (our `get_elem_tactic`) bound loop indices `i ∈ [a:b]`. -/
@[local grind =] private theorem mem_range (x a b : ℕ) : x ∈ [a:b] ↔ a ≤ x ∧ x < b := by
  simp [Membership.mem, Nat.mod_one]

/-- * `SK_SIZE = 32` -/
def SK_SIZE : ℕ := 32

/-! Domain separators:
  * `DOMSEP_KGEXPAND = 0x01`
  * `DOMSEP_GENMAT = 0x02`
  * `DOMSEP_GENSEC = 0x03`
  * `DOMSEP_PKHASH = 0x04`
  * `DOMSEP_FO = 0x05`
  * `DOMSEP_NOREJECT = 0x06` -/
abbrev DOMSEP_KGEXPAND : Byte := 0x01
abbrev DOMSEP_GENMAT : Byte := 0x02
abbrev DOMSEP_GENSEC : Byte := 0x03
abbrev DOMSEP_PKHASH : Byte := 0x04
abbrev DOMSEP_FO : Byte := 0x05
abbrev DOMSEP_NOREJECT : Byte := 0x06

/-- We use the TurboSHAKE XOF family defined in [RFC 9861]. We invoke it as
`TurboSHAKE128/TurboSHAKE256(M, L, D)`, where `M` is the message to be hashed, `L` is the desired
output length, and `D` is the domain separator in the range `[0x01, 0x7f]`. -/
def TurboSHAKE128 {m : ℕ} (M : 𝔹 m) (L : ℕ) (D : Byte) (h : 0 < D ∧ D < 0x80 := by decide) :
    𝔹 L := Wychelean.Hashes.TurboSHAKE.turboShake128 M D L h

def TurboSHAKE256 {m : ℕ} (M : 𝔹 m) (L : ℕ) (D : Byte) (h : 0 < D ∧ D < 0x80 := by decide) :
    𝔹 L := Wychelean.Hashes.TurboSHAKE.turboShake256 M D L h

/-- `s[a..a+len]`. Indices past the end of `s` read as `default`; the spec never uses one. -/
def slice {α : Type} [Inhabited α] {n : ℕ} (s : Vector α n) (a len : ℕ) : Vector α len :=
  Vector.ofFn fun j => s[a + j.val]!

/-- `s[a..a+k] = t`, for `t` of length `k`. -/
def _root_.Vector.setSlice {α : Type} {n k : ℕ} (s : Vector α n) (a : ℕ) (t : Vector α k) :
    Vector α n :=
  Vector.ofFn fun j => if h : a ≤ j.val ∧ j.val - a < k then t[j.val - a] else s[j]

/-- We define `to_bits_le(n: ℤ, k: un) -> [bool; n]` to be the function that converts an `n`-bit
integer to its bit representation, starting with the least significant bit. -/
def to_bits_le (n k : ℕ) : Vector Bool n := Vector.ofFn fun i => k.testBit i

/-- Similarly, we define `from_bits_le(n: ℤ, bits: [bool; n]) -> un` to interpret `n` bits as a
`un` value, using `bits[0]` as the least significant bit of the output, and so on. -/
def from_bits_le (n : ℕ) (bits : Vector Bool n) : ℕ := ∑ i : Fin n, bits[i].toNat * 2 ^ i.val

/-- Let `R` be the negacyclic polynomial ring `ℤ[X]/(X²⁵⁶ + 1)`. We denote by `R13` the polynomial
ring modulo `2^13`, i.e., `R/2¹³R` (this is isomorphic to `(ℤ/2¹³ℤ)[X]/(X²⁵⁶ + 1)`). Similarly,
`R10` denotes `R/2¹⁰R` and `R1` denotes `R/2R`.

For any modulus `N`, we say the canonical form of an element of `ℤ/Nℤ` is its representative
integer in `[0, N)`.

`Poly m` is `(ℤ/mℤ)[X]/(X²⁵⁶ + 1)`, as its 256 coefficients, lowest degree first. `R n` is
`Rn`. -/
abbrev Poly (m : ℕ) := Vector (ZMod m) 256

abbrev R (n : ℕ) := Poly (2 ^ n)

def Poly.zero (m : ℕ) : Poly m := Vector.replicate 256 0

def Poly.add {m : ℕ} (f g : Poly m) : Poly m := Vector.zipWith (· + ·) f g

def Poly.sub {m : ℕ} (f g : Poly m) : Poly m := Vector.zipWith (· - ·) f g

/-- The naive negacyclic convolution. -/
def Poly.mul {m : ℕ} (a b : Poly m) : Poly m := Id.run do
  let mut c := Poly.zero m
  for hi : i in [0:256] do
    for hj : j in [0:256] do
      let k := (i + j) % 256
      have hk : k < 256 := Nat.mod_lt _ (by decide)
      if i + j < 256 then
        c := c.set k (c[k] + a[i] * b[j])
      else
        c := c.set k (c[k] - a[i] * b[j])
  pure c

instance {m : ℕ} : Zero (Poly m) where zero := Poly.zero m
instance {m : ℕ} : Add (Poly m) where add := Poly.add
instance {m : ℕ} : Sub (Poly m) where sub := Poly.sub
instance {m : ℕ} : Mul (Poly m) where mul := Poly.mul

/-- For an element `r` in `Rn` and integer `N`, we define the right-shift `r >> N` as
`make_rn([a_0 >> N, a_1 >> N, ..., a_255 >> N])` where `a_i` are the canonical coefficients of `r`. -/
def Poly.shiftRight {m : ℕ} (r : Poly m) (N : ℕ) : Poly m :=
  r.map (fun a => ((a.val >>> N : ℕ) : ZMod m))

/-- We define left-shift `r << N` similarly, with coefficients reduced mod `2^n`. -/
def Poly.shiftLeft {m : ℕ} (r : Poly m) (N : ℕ) : Poly m :=
  r.map (fun a => ((a.val <<< N : ℕ) : ZMod m))

instance {m : ℕ} : HShiftRight (Poly m) ℕ (Poly m) where hShiftRight := Poly.shiftRight
instance {m : ℕ} : HShiftLeft (Poly m) ℕ (Poly m) where hShiftLeft := Poly.shiftLeft

/-- When we write `r as U` for some type `U`, we mean to invoke either the natural injection or
projection of `r` into/onto `U`. For example, if `r` is in `VecR10` and `U` is `VecR13`, then it is
the natural injection, and if vice-versa, then it is the natural projection by quotienting by
`2¹⁰R13`. -/
def Poly.coerce {m : ℕ} (r : Poly m) (m' : ℕ) : Poly m' := r.map (fun a => (a.val : ZMod m'))

def Poly.as_rn {m : ℕ} (r : Poly m) (n : ℕ) : R n := r.coerce (2 ^ n)

/-- The type `VecRn` refers to `Rn^ℓ`, i.e., vectors of `ℓ` elements of `Rn`. When indexing into a
vector `v: VecRn` for some `n`, we do so in the same order that was used in its constructor, i.e.,
`v[i]` equals `a[i]` where `a` is the input to the `make_vecn` that constructed `v`. -/
abbrev PolyVector (m ℓ : ℕ) := Vector (Poly m) ℓ

abbrev VecR (n ℓ : ℕ) := PolyVector (2 ^ n) ℓ

instance {m ℓ : ℕ} : Add (PolyVector m ℓ) where add v w := Vector.ofFn fun i => v[i] + w[i]
instance {m ℓ : ℕ} : Sub (PolyVector m ℓ) where sub v w := Vector.ofFn fun i => v[i] - w[i]

/-- We define right and left shift for elements of `VecRn` as operating element-wise. -/
def PolyVector.shiftRight {m ℓ : ℕ} (v : PolyVector m ℓ) (N : ℕ) : PolyVector m ℓ :=
  v.map (·.shiftRight N)

instance {m ℓ : ℕ} : HShiftRight (PolyVector m ℓ) ℕ (PolyVector m ℓ) where
  hShiftRight := PolyVector.shiftRight

/-- When we write `r as U` for some type `U`, we mean to invoke either the natural injection or
projection of `r` into/onto `U`. -/
def PolyVector.coerce {m ℓ : ℕ} (v : PolyVector m ℓ) (m' : ℕ) : PolyVector m' ℓ :=
  v.map (·.coerce m')

def PolyVector.as_vecn {m ℓ : ℕ} (v : PolyVector m ℓ) (n : ℕ) : VecR n ℓ := v.coerce (2 ^ n)

/-- `Poly m` adds like `(ℤ/mℤ)²⁵⁶`, so `∑` makes sense below. -/
instance polyAddCommMonoid {m : ℕ} : AddCommMonoid (Poly m) where
  add := Poly.add
  zero := Poly.zero m
  nsmul := nsmulRec
  add_assoc a b c := by
    show Poly.add (Poly.add a b) c = Poly.add a (Poly.add b c)
    apply Vector.ext; intro p hp
    simp only [Poly.add, Vector.getElem_zipWith]; ring
  zero_add a := by
    show Poly.add (Poly.zero m) a = a
    apply Vector.ext; intro p hp
    simp only [Poly.add, Poly.zero, Vector.getElem_zipWith, Vector.getElem_replicate]; ring
  add_zero a := by
    show Poly.add a (Poly.zero m) = a
    apply Vector.ext; intro p hp
    simp only [Poly.add, Poly.zero, Vector.getElem_zipWith, Vector.getElem_replicate]; ring
  add_comm a b := by
    show Poly.add a b = Poly.add b a
    apply Vector.ext; intro p hp
    simp only [Poly.add, Vector.getElem_zipWith]; ring

/-- `transpose` transposes the given matrix or vector. -/
structure PolyRowVector (m ℓ : ℕ) where
  col : PolyVector m ℓ

instance {m ℓ : ℕ} : HMul (PolyRowVector m ℓ) (PolyVector m ℓ) (Poly m) where
  hMul v w := ∑ i : Fin ℓ, v.col[i] * w[i]

/-- The type `MatRn` refers to `Rn^(ℓ×ℓ)`, i.e., `ℓ×ℓ` matrices of elements of `Rn`, for any
`n`. -/
abbrev PolyMatrix (m ℓ : ℕ) := Matrix (Fin ℓ) (Fin ℓ) (Poly m)

abbrev MatR (n ℓ : ℕ) := PolyMatrix (2 ^ n) ℓ

instance {m ℓ : ℕ} : HMul (PolyMatrix m ℓ) (PolyVector m ℓ) (PolyVector m ℓ) where
  hMul A v := Vector.ofFn fun i => ∑ j : Fin ℓ, A i j * v[j]

/-- For any `n`, we write `make_rn` to refer to the natural morphism from the space of
coefficients `[un; 256]` to `Rn` (input is interpreted lowest-degree-coefficient-first). -/
def make_rn (n : ℕ) (coeffs : Vector ℤ 256) : R n := coeffs.map (↑)

/-- `make_vecn` takes an array `[Rn; ℓ]` and interprets it as a column vector in `VecRn`, in the
same order as `make_matn`, i.e., such that `make_matn([eye, zeros, ... zeros]) * make_vecn(eye) =
make_vecn(eye)`, where `eye = [1, 0, ..., 0]`, and `zeros = [0, 0, ..., 0]`. -/
def make_vecn {ℓ : ℕ} (n : ℕ) (elems : Vector (R n) ℓ) : VecR n ℓ := elems

/-- `make_matn` takes a nested array `[[Rn; ℓ]; ℓ]` and interprets it as a list of rows in a
matrix in `MatRn`. -/
def make_matn {ℓ : ℕ} (n : ℕ) (rows : Vector (Vector (R n) ℓ) ℓ) : MatR n ℓ :=
  Matrix.of fun i j => rows[i][j]

/-- For any `n` and a ring element `r` we say its _canonical coefficients_
`canonical_coeffs(r: Rn) -> [un; 256]` are the unique sequence of 256 `un` values `a_0, ..., a_255`
such that `r = a_255 X^255 + ... + a_1 X + a_0`. -/
def canonical_coeffs {n : ℕ} (r : R n) : Vector ℕ 256 := r.map (·.val)

/-- `transpose` transposes the given matrix or vector. -/
def PolyVector.transpose {m ℓ : ℕ} (v : PolyVector m ℓ) : PolyRowVector m ℓ := ⟨v⟩

export Matrix (transpose)
export PolyVector (transpose)

/-- Serializes an element of Rn (for any choice n=13,10,1,t)
```
fn serialize_elem(n: ℤ, r: Rn) -> [u8; n*256/8]:
  let a = canonical_coeffs(r)

  let all_bits: [bool; n*256]
  for i in 0..256:
    all_bits[n*i..n*(i+1)] = to_bits_le(n, a[i])

  let out: [u8; 32*n]
  for i in 0..32*n:
    out[i] = from_bits_le(8, all_bits[8*i..8*(i+1)])
  return out
```
-/
def serialize_elem (n : ℕ) (r : R n) : 𝔹 (n * 256 / 8) := Id.run do
  let a := canonical_coeffs r

  let mut all_bits := Vector.replicate (n * 256) false
  for h : i in [0:256] do
    all_bits := all_bits.setSlice (n * i) (to_bits_le n a[i])

  let mut out := Vector.replicate (n * 256 / 8) (0 : Byte)
  for h : i in [0:32 * n] do
    out := out.set i (from_bits_le 8 (slice all_bits (8 * i) 8))
  return out

/-- Deserializes an element of Rn (for any choice n=13,10,1,t)
```
fn deserialize_elem(n: ℤ, bytes: [u8; n*256/8]) -> Rn:
  let all_bits: [bool; n*256]
  for i in 0..n*32:
    all_bits[8*i..8*(i+1)] = to_bits_le(8, bytes[i])

  let coeffs: [un; 256]
  for i in 0..256:
    coeffs[i] = from_bits_le(n, all_bits[n*i..n*(i+1)])
  return make_rn(coeffs)
```
-/
def deserialize_elem (n : ℕ) (bytes : 𝔹 (n * 256 / 8)) : R n := Id.run do
  let mut all_bits := Vector.replicate (n * 256) false
  for h : i in [0:n * 32] do
    all_bits := all_bits.setSlice (8 * i) (to_bits_le 8 bytes[i].toNat)

  let mut coeffs := Vector.replicate 256 (0 : ℤ)
  for h : i in [0:256] do
    coeffs := coeffs.set i (from_bits_le n (slice all_bits (n * i) n))
  return make_rn n coeffs

/-- The following variables represent security parameters, and depend on the security level being
instantiated:

* `ℓ` — The public matrix dimension. This impacts the size of public keys and ciphertexts
* `μ` — The binomial parameter used for secret generation. This is always even.
* `t` — The base-2 logarithm of the modulus of the space of compressed ring elements -/
structure ParameterSet where
  ℓ : ℕ
  t : ℕ
  μ : ℕ

/-- * `PK_SIZE = 256*ℓ*10/8 + 32` -/
def ParameterSet.PK_SIZE (P : ParameterSet) : ℕ := 256 * P.ℓ * 10 / 8 + 32

/-- * `CT_SIZE = 256*t/8 + 256*ℓ*10/8` -/
def ParameterSet.CT_SIZE (P : ParameterSet) : ℕ := 256 * P.t / 8 + 256 * P.ℓ * 10 / 8

section
variable (P : ParameterSet)

mutual

/-- ```
fn SkToPk(sk: [u8; 32]) -> [u8; PK_SIZE]:
  let (_, _, pk, _) = ExpandSecretKey(sk)
  return pk
```
-/
def SkToPk (sk : 𝔹 32) : 𝔹 P.PK_SIZE := Id.run do
  let (_, _, pk, _) := ExpandSecretKey sk
  return pk

/-- ```
fn PkeEncrypt(
  randomness: [u8; 32],
  pk: [u8; PK_SIZE],
  msg: [u8; 32]
) -> [u8; CT_SIZE]:
  let vec_b = deserialize_vec(10, pk[..256*ℓ*10/8])
  let mat_seed = pk[256*ℓ*10/8..]
  let m = deserialize_elem(1, msg)

  let mat_A = GenMat(mat_seed)
  let vec_sprime = GenSecret(randomness)
  let vec_bprime = CompressToR10(mat_A * vec_sprime)
  let vprime = transpose(vec_b) * (vec_sprime as VecR10)
  let cm = CompressToRt(vprime - ((m as R10) << 9))

  let ct = serialize_vec(10, vec_bprime) || serialize_elem(t, cm)
  return ct
```
-/
def PkeEncrypt (randomness : 𝔹 32) (pk : 𝔹 P.PK_SIZE) (msg : 𝔹 32) : 𝔹 P.CT_SIZE := Id.run do
  let vec_b := deserialize_vec 10 (slice pk 0 (256 * P.ℓ * 10 / 8))
  let mat_seed := slice pk (256 * P.ℓ * 10 / 8) 32
  let m := deserialize_elem 1 msg

  let mat_A := GenMat mat_seed
  let vec_sprime := GenSecret randomness
  let vec_bprime := CompressToR10 (mat_A * vec_sprime)
  let vprime := transpose vec_b * vec_sprime.as_vecn 10
  let cm := CompressToRt (vprime - (m.as_rn 10 <<< 9))

  let ct := serialize_vec 10 vec_bprime ‖ serialize_elem P.t cm
  return ct.cast (by simp only [ParameterSet.CT_SIZE]; omega)

/-- ```
fn PkeDecrypt(sk: [u8; 32], ct: [u8; CT_SIZE]) -> [u8; 32]:
  let (vec_s, ...) = ExpandSecretKey(sk)
  let vec_bprime = deserialize_vec(10, ct[..256*ℓ*10/8])
  let cm = deserialize_elem(t, ct[256*ℓ*10/8..])
  let v = transpose(vec_bprime) * (vec_s as VecR10)
  let cm10 = (cm as R10) << (10 - t)
  let mprime = DecodeMsg(v - cm10)
  return serialize_elem(1, mprime)
```
-/
def PkeDecrypt (sk : 𝔹 32) (ct : 𝔹 P.CT_SIZE) : 𝔹 32 := Id.run do
  let (vec_s, _, _, _) := ExpandSecretKey sk
  let vec_bprime := deserialize_vec 10 (slice ct 0 (256 * P.ℓ * 10 / 8))
  let cm := deserialize_elem P.t (slice ct (256 * P.ℓ * 10 / 8) (P.t * 256 / 8))
  let v := transpose vec_bprime * vec_s.as_vecn 10
  let cm10 := cm.as_rn 10 <<< (10 - P.t)
  let mprime := DecodeMsg (v - cm10)
  return serialize_elem 1 mprime

/-- ```
fn KemEncap(
  randomness: [u8; 32],
  pk: [u8; PK_SIZE]
) -> ([u8; 32], [u8; CT_SIZE]):
  # Derive the output key and encryption randomness
  let pkh = TurboSHAKE256(pk, 32, DOMSEP_PKHASH)
  let b = TurboSHAKE256(randomness || pkh, 64, DOMSEP_FO)
  let (k, r) = (b[..32], b[32..])

  # Encrypt to pk. `randomness` is itself the message
  let ct = PkeEncrypt(r, pk, randomness)

  return (k, ct)
```
-/
def KemEncap (randomness : 𝔹 32) (pk : 𝔹 P.PK_SIZE) : 𝔹 32 × 𝔹 P.CT_SIZE := Id.run do
  -- Derive the output key and encryption randomness
  let pkh := TurboSHAKE256 pk 32 DOMSEP_PKHASH
  let b := TurboSHAKE256 (randomness ‖ pkh) 64 DOMSEP_FO
  let (k, r) := (slice b 0 32, slice b 32 32)

  -- Encrypt to pk. `randomness` is itself the message
  let ct := PkeEncrypt r pk randomness

  return (k, ct)

/-- ```
fn KemDecap(sk: [u8; 32], ct: [u8; CT_SIZE]) -> [u8; 32]:
  let (_, z, pk, pkh) = ExpandSecretKey(sk)

  let randomness = PkeDecrypt(sk, ct)
  let b = TurboSHAKE256(randomness || pkh, 64, DOMSEP_FO)
  let (k, rprime) = (b[..32], b[32..])
  let cprime = PkeEncrypt(rprime, pk, randomness)

  if ct == cprime:
    return k
  else:
    return TurboSHAKE256(z || ct, 32, DOMSEP_NOREJECT)
```
We note again that, along with all other top-level functions, `KemDecap` MUST be constant time
with respect to its inputs. In particular, an implementer MUST perform the ciphertext equality
check in constant time. -/
def KemDecap (sk : 𝔹 32) (ct : 𝔹 P.CT_SIZE) : 𝔹 32 := Id.run do
  let (_, z, pk, pkh) := ExpandSecretKey sk

  let randomness := PkeDecrypt sk ct
  let b := TurboSHAKE256 (randomness ‖ pkh) 64 DOMSEP_FO
  let (k, rprime) := (slice b 0 32, slice b 32 32)
  let cprime := PkeEncrypt rprime pk randomness

  if ct == cprime then
    return k
  else
    return TurboSHAKE256 (z ‖ ct) 32 DOMSEP_NOREJECT

/-- ```
fn ExpandSecretKey(
  sk: [u8; 32]
) -> (VecR13, [u8; 32], [u8; PK_SIZE], [u8; 32]):
  let randomness = TurboSHAKE256(sk || (ℓ as u8), 96, DOMSEP_KGEXPAND)
  let mat_seed = randomness[..32]
  let secret_seed = randomness[32..64]
  let z = randomness[64..]

  let mat_A = GenMat(mat_seed)
  let vec_s = GenSecret(secret_seed)
  let vec_b = CompressToR10(transpose(mat_A) * vec_s)
  let pk = serialize_vec(10, vec_b) || mat_seed
  let pkh = TurboSHAKE256(pk, 32, DOMSEP_PKHASH)

  return (vec_s, z, pk, pkh)
```
-/
def ExpandSecretKey (sk : 𝔹 32) : VecR 13 P.ℓ × 𝔹 32 × 𝔹 P.PK_SIZE × 𝔹 32 := Id.run do
  let randomness := TurboSHAKE256 (sk ‖ #v[(P.ℓ : Byte)]) 96 DOMSEP_KGEXPAND
  let mat_seed := slice randomness 0 32
  let secret_seed := slice randomness 32 32
  let z := slice randomness 64 32

  let mat_A := GenMat mat_seed
  let vec_s := GenSecret secret_seed
  let vec_b := CompressToR10 (transpose mat_A * vec_s)
  let pk := serialize_vec 10 vec_b ‖ mat_seed
  let pkh := TurboSHAKE256 pk 32 DOMSEP_PKHASH

  return (vec_s, z, pk, pkh)

/-- ```
fn CompressToR10(v: VecR13) -> VecR10:
  let h1 = make_r13([4u13; 256])
  let h = make_vec13([h1; ℓ])
  let s = (v + h) >> 3
  return (s as VecR10)
```
-/
def CompressToR10 (v : VecR 13 P.ℓ) : VecR 10 P.ℓ := Id.run do
  let h1 := make_rn 13 (Vector.replicate 256 4)
  let h := make_vecn 13 (Vector.replicate P.ℓ h1)
  let s := (v + h) >>> 3
  return s.as_vecn 10

/-- ```
fn CompressToRt(r: R10) -> Rt:
  let h1 = make_r10([4u10; 256])
  let s = (r + h1) >> (10 - t)
  return (s as Rt)
```
-/
def CompressToRt (r : R 10) : R P.t := Id.run do
  let h1 := make_rn 10 (Vector.replicate 256 4)
  let s := (r + h1) >>> (10 - P.t)
  return s.as_rn P.t

/-- ```
fn DecodeMsg(r: R10) -> R1:
  let h2 = make_r10([2^8 - 2^(10-t-1) + 4; 256])
  let s = (r + h2) >> 9
  return (s as R1)
```
-/
def DecodeMsg (r : R 10) : R 1 := Id.run do
  let h2 := make_rn 10 (Vector.replicate 256 (2 ^ 8 - 2 ^ (10 - P.t - 1) + 4))
  let s := (r + h2) >>> 9
  return s.as_rn 1

/-- ```
fn GenMat(seed: [u8; 32]) -> MatR13:
  let A: [[R13; ℓ]; ℓ]
  for i in 0u8..ℓ:
    for j in 0u8..ℓ:
      let buf = TurboSHAKE128(seed || i || j, 256*13/8, DOMSEP_GENMAT)
      A[i][j] = deserialize_elem(13, buf)
  return make_mat13(A)
```
-/
def GenMat (seed : 𝔹 32) : MatR 13 P.ℓ := Id.run do
  let mut A := Vector.replicate P.ℓ (Vector.replicate P.ℓ (0 : R 13))
  for hi : i in [0:P.ℓ] do
    for hj : j in [0:P.ℓ] do
      let buf := TurboSHAKE128 (seed ‖ #v[(i : Byte)] ‖ #v[(j : Byte)]) (256 * 13 / 8) DOMSEP_GENMAT
      A := A.set i (A[i].set j (deserialize_elem 13 buf))
  return make_matn 13 A

/-- ```
fn GenSecret(seed: [u8; 32]) -> VecR13:
  let s: [R13; ℓ]
  for i in 0u8..ℓ:
    let buf = TurboSHAKE256(seed || i, μ*256/8, DOMSEP_GENSEC)
    let vals = bit_slices(buf)
    let r: [u13; 256]
    for k in 0..256:
      # Recall subtraction is wrapping
      r[k] = hamming(vals[2*k]) - hamming(vals[2*k+1])
    s[i] = make_r13(r)
  return make_vec13(s)
```
-/
def GenSecret (seed : 𝔹 32) : VecR 13 P.ℓ := Id.run do
  let mut s := Vector.replicate P.ℓ (0 : R 13)
  for hi : i in [0:P.ℓ] do
    let buf := TurboSHAKE256 (seed ‖ #v[(i : Byte)]) (P.μ * 256 / 8) DOMSEP_GENSEC
    let vals := bit_slices buf
    let mut r := Vector.replicate 256 (0 : ℤ)
    for hk : k in [0:256] do
      r := r.set k ((hamming vals[2 * k] - hamming vals[2 * k + 1] : ℤ) % 2 ^ 13)
    s := s.set i (make_rn 13 r)
  return make_vecn 13 s

/-- Serializes an element of VecRn (for any choice n=13,10,1,t)
```
fn serialize_vec(n: ℤ, v: VecRn) -> [u8; ℓ*n*256/8]:
  let out: [u8; ℓ*n*32]
  for i in 0..ℓ:
    out[n*32*i..n*32*(i+1)] = serialize_elem(n, v[i])
  return out
```
-/
def serialize_vec (n : ℕ) (v : VecR n P.ℓ) : 𝔹 (256 * P.ℓ * n / 8) := Id.run do
  let mut out := Vector.replicate (256 * P.ℓ * n / 8) (0 : Byte)
  for h : i in [0:P.ℓ] do
    out := out.setSlice (n * 32 * i) (serialize_elem n v[i])
  return out

/-- Deserializes an element of VecRn (for any choice n=13,10,1,t)
```
fn deserialize_vec(n: ℤ, bytes: [u8; ℓ*n*256/8]) -> VecRn:
  let elems: [Rn; ℓ]
  for i in 0..ℓ:
    elems[i] = deserialize_elem(n, bytes[n*32*i..n*32*(i+1)])
  return make_vecn(elems)
```
-/
def deserialize_vec (n : ℕ) (bytes : 𝔹 (256 * P.ℓ * n / 8)) : VecR n P.ℓ := Id.run do
  let mut elems := Vector.replicate P.ℓ (0 : R n)
  for h : i in [0:P.ℓ] do
    elems := elems.set i (deserialize_elem n (slice bytes (n * 32 * i) (n * 256 / 8)))
  return make_vecn n elems

/-- Reinterprets a bytestring as a sequence of bitstrings of length μ/2
```
fn bit_slices(bytes: [u8; μ*256/8]) -> [[bool; μ/2]; 512]:
  let all_bits: [bool; μ*256]
  for i in 0..μ*32:
    all_bits[8*i..8*(i+1)] = to_bits_le(8, bytes[i])

  let out: [[bool; μ/2]; 512]
  for i in 0..512:
    out[i] = all_bits[i*μ/2..(i+1)*μ/2]
  return out
```
-/
def bit_slices (bytes : 𝔹 (P.μ * 256 / 8)) : Vector (Vector Bool (P.μ / 2)) 512 := Id.run do
  let mut all_bits := Vector.replicate (P.μ * 256) false
  for h : i in [0:P.μ * 32] do
    all_bits := all_bits.setSlice (8 * i) (to_bits_le 8 bytes[i].toNat)

  let mut out := Vector.replicate 512 (Vector.replicate (P.μ / 2) false)
  for h : i in [0:512] do
    out := out.set i (slice all_bits (i * P.μ / 2) (P.μ / 2))
  return out

/-- Returns the number of set bits in b
```
fn hamming(b: [bool; μ/2]) -> u13:
  let mut weight = 0u13
  for i in 0..μ/2:
    if b[i]:
      weight += 1
  return weight
```
-/
def hamming (b : Vector Bool (P.μ / 2)) : ℕ := Id.run do
  let mut weight := 0
  for h : i in [0:P.μ / 2] do
    if b[i] then
      weight := weight + 1
  return weight

end

end

/-- |Name       | Parameters     | `PK_SIZE` | `CT_SIZE` | `SK_SIZE` |
|---------- |----------------|-----------|-----------|-----------|
|Kopis-512  | `ℓ=2 t=3 μ=10` | 672       | 736       | 32        |
|Kopis-768  | `ℓ=3 t=4 μ=8`  | 992       | 1088      | 32        |
|Kopis-1024 | `ℓ=4 t=6 μ=6`  | 1312      | 1472      | 32        | -/
def ParameterSet.Kopis_512 : ParameterSet := { ℓ := 2, t := 3, μ := 10 }
def ParameterSet.Kopis_768 : ParameterSet := { ℓ := 3, t := 4, μ := 8 }
def ParameterSet.Kopis_1024 : ParameterSet := { ℓ := 4, t := 6, μ := 6 }

example : (ParameterSet.Kopis_512.PK_SIZE, ParameterSet.Kopis_512.CT_SIZE) = (672, 736) := rfl
example : (ParameterSet.Kopis_768.PK_SIZE, ParameterSet.Kopis_768.CT_SIZE) = (992, 1088) := rfl
example : (ParameterSet.Kopis_1024.PK_SIZE, ParameterSet.Kopis_1024.CT_SIZE) = (1312, 1472) := rfl

end Kopis
