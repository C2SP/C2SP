# Kopis in Lean

`Kopis.lean` is a running Lean specification of the Kopis KEM, transcribed function-by-function from the Markdown specification.

## How to run

This requires that Lean be installed. See [here](https://lean-lang.org/install/manual/) for instructions.

1. Fetch the Mathlib cache so the build doesn't take forever: `lake exe cache get`
2. Now check the spec: `lake build`
3. Fetch the JSONL test vectors from [CCTV](https://github.com/C2SP/CCTV/tree/main/kopis) and place them in this directory.
4. Run known-answer tests: `lake exe kopisKats`. This will take several minutes.
