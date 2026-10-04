import Kopis
import Lean.Data.Json

/-! Known-answer tests, from `kopis-rs`'s `tests/test_vectors-kopis*.jsonl`. Run from the package
root with `lake exe kopisTests`. -/

open Kopis Lean

/-- One line of a `.jsonl` vector file. Byte fields are hex. -/
structure KopisVector where
  description : String
  sk : String
  pk : String
  encap_randomness : String
  encapper_ct : String
  decapper_ct : String
  encapper_ss : String
  decapper_ss : String
  malformed : Bool
  deriving FromJson

/-- Parses hex into exactly `n` bytes. -/
def hex? (n : ℕ) (s : String) : Option (𝔹 n) := do
  let digit (c : Char) : Option ℕ :=
    if c.isDigit then some (c.toNat - '0'.toNat)
    else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
    else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10) else none
  let ds ← s.toList.mapM digit
  let bytes := (List.range (ds.length / 2)).map fun i => (16 * ds[2 * i]! + ds[2 * i + 1]!).toUInt8
  if h : ds.length % 2 = 0 ∧ bytes.length = n then some ⟨bytes.toArray, by simp [h.2]⟩ else none

def runKAT (P : ParameterSet) (path : System.FilePath) : IO Unit := do
  IO.println s!"{path} ..."
  let mut n := 0
  for line in ← IO.FS.lines path do
    if line.trimAscii.isEmpty then continue
    let v : KopisVector ← IO.ofExcept (Json.parse line >>= fromJson?)
    let fail (what : String) : IO Unit := throw (.userError s!"{path}: {v.description}: {what}")
    match hex? 32 v.sk, hex? P.PK_SIZE v.pk, hex? 32 v.encap_randomness, hex? P.CT_SIZE v.encapper_ct,
        hex? P.CT_SIZE v.decapper_ct, hex? 32 v.encapper_ss, hex? 32 v.decapper_ss with
    | some sk, some pk, some er, some ect, some dct, some ess, some dss =>
      if v.malformed then fail "malformed vector has valid sizes"
      if SkToPk P sk != pk then fail "SkToPk"
      if KemEncap P er pk != (ess, ect) then fail "KemEncap"
      if KemDecap P sk dct != dss then fail "KemDecap"
    -- Every malformed vector has a wrong length, which the spec's types rule out
    | _, _, _, _, _, _, _ => if !v.malformed then fail "bad hex"
    n := n + 1
  IO.println s!"    all {n} vectors OK"

def main : IO Unit := do
  runKAT .Kopis_512 "test_vectors-kopis512.jsonl"
  runKAT .Kopis_768 "test_vectors-kopis768.jsonl"
  runKAT .Kopis_1024 "test_vectors-kopis1024.jsonl"
