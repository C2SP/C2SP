import Blake3
import Lean.Data.Json

/-! Known-answer tests: the specification's appendix and the official test vectors it links.

    lake env lean --run Tests.lean traces.json test_vectors.json

`traces.json` is the appendix's two traces, extracted from `BLAKE3.md` by `check.py`: each
compression's inputs, its output, and (in the first) the state after each round. `test_vectors.json`
is the file the appendix links, at the commit it names. -/

open Lean Blake3

def hexByte (b : UInt8) : String :=
  let d := "0123456789abcdef".toList
  s!"{d[b.toNat / 16]!}{d[b.toNat % 16]!}"

def hex (b : ByteArray) : String := String.join (b.toList.map hexByte)

def unhex (s : String) : ByteArray := Id.run do
  let digit (c : Char) : Nat := if c.isDigit then c.toNat - '0'.toNat else c.toNat - 'a'.toNat + 10
  let cs := s.toList.toArray
  let mut out := ByteArray.empty
  for i in [0:cs.size / 2] do
    out := out.push (16 * digit cs[2 * i]! + digit cs[2 * i + 1]!).toUInt8
  return out

def vec (n : Nat) (ws : Array Nat) : Vector Word n := Vector.ofFn fun i => (ws[i.val]!).toUInt32

def check (ok : Bool) (what : String) : IO Unit :=
  unless ok do throw (.userError s!"MISMATCH: {what}")

def getNats (j : Json) (k : String) : IO (Array Nat) := IO.ofExcept do
  (← (← j.getObjVal? k).getArr?).mapM fun x => x.getNat?

def main (args : List String) : IO Unit := do
  let [traces, vectors] := args | throw (.userError "usage: Tests.lean traces.json test_vectors.json")
  -- The appendix.
  let ts ← IO.ofExcept (Json.parse (← IO.FS.readFile traces))
  let mut compressions := 0
  for ex in ← IO.ofExcept ts.getArr? do
    let title ← IO.ofExcept (ex.getObjValAs? String "title")
    let len := (← IO.ofExcept (ex.getObjValAs? Nat "len")).toUInt32
    for c in ← IO.ofExcept ((← IO.ofExcept (ex.getObjVal? "compressions")).getArr?) do
      let label ← IO.ofExcept (c.getObjValAs? String "label")
      let h := vec 8 (← getNats c "h"); let m := vec 16 (← getNats c "m")
      let t ← getNats c "t"
      let counter : Counter := t[0]!.toUInt64 ||| (t[1]!.toUInt64 <<< 32)
      let flags := (← IO.ofExcept (c.getObjValAs? Nat "flags")).toUInt32
      let out := BLAKE3_COMPRESS h m counter len flags
      let want ← getNats c "out"
      check ((List.range want.size).all fun i => out.toArray[i]!.toNat == want[i]!) s!"{title}, {label}: the output"
      let rounds ← IO.ofExcept (((← IO.ofExcept (c.getObjVal? "rounds")).getArr?))
      let trace := BLAKE3_COMPRESS_TRACE h m counter len flags
      for r in [0:rounds.size] do
        let state ← IO.ofExcept ((rounds[r]!.getArr?) >>= (·.mapM (·.getNat?)))
        check (trace[r]!.toArray.toList.map (·.toNat) == state.toList) s!"{title}, {label}: after round {r}"
      compressions := compressions + 1
    let input := unhex (← IO.ofExcept (ex.getObjValAs? String "input_hex"))
    let key := unhex (← IO.ofExcept (ex.getObjValAs? String "key_hex"))
    let got := if key.size == 0 then Blake3.hash input else keyed_hash key input
    check (hex got == (← IO.ofExcept (ex.getObjValAs? String "hash"))) s!"{title}: the hash value"
  IO.println s!"Tests.lean: the appendix's {compressions} compressions, their round states, and both hash values reproduced"
  -- The official test vectors.
  let vs ← IO.ofExcept (Json.parse (← IO.FS.readFile vectors))
  let key := (← IO.ofExcept (vs.getObjValAs? String "key")).toUTF8
  let context := (← IO.ofExcept (vs.getObjValAs? String "context_string")).toUTF8
  let cases ← IO.ofExcept ((← IO.ofExcept (vs.getObjVal? "cases")).getArr?)
  let mut longest := 0
  for c in cases do
    let n ← IO.ofExcept (c.getObjValAs? Nat "input_len")
    let input : ByteArray := ⟨(Array.range n).map fun i => (i % 251).toUInt8⟩
    for (field, f) in [("hash", fun (len : Nat) => Blake3.hash input len),
                       ("keyed_hash", fun len => keyed_hash key input len),
                       ("derive_key", fun len => derive_key context input len)] do
      let want ← IO.ofExcept (c.getObjValAs? String field)
      check (hex (f (want.length / 2)) == want) s!"test vector {n}, {field}"
      longest := max longest (want.length / 2)
  IO.println s!"Tests.lean: all {cases.size} official test vectors reproduced, hash, keyed_hash, and derive_key, up to {longest} bytes of output"
