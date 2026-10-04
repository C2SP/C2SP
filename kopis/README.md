# Kopis in Lean

`Kopis.lean` is a running Lean specification of the Kopis KEM, transcribed function by function from the Markdown specification.

## How to run

First off, Lean should be installed. See [here](https://lean-lang.org/install/manual/) for instructions.

1. First, fetch the Mathlib cache so the build doesn't take forever: `lake exe cache get`
2. Now check the spec `lake build`
3. Fetch the JSONL test vectors from [CCTV](https://github.com/rozbb/CCTV/tree/main/kopis) and place them in this directory.
3. Run known-answer tests: `lake exec kopisKats`
