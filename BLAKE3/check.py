"""Check that Blake3.lean matches BLAKE3.md.

    python3 check.py [path/to/BLAKE3.md]     (default: ../BLAKE3.md)

1. Sections 2.2 to 3.3: generate.py's translation of BLAKE3.md equals the
   generated section of Blake3.lean, byte for byte.
2. The appendix: every value of its two traces (each compression's inputs and
   output, the state after each round, the hash values) is extracted, the
   document's own conventions applied (a block's message, counter, and flags
   carry over until the trace shows them again; `len` is 64 unless the text
   says otherwise), and the trace checked for consistency with itself (each
   block's `h` is the previous output; the messages are the ones the text
   describes). Lean then reproduces every value (Tests.lean).
3. The official test vectors the appendix links, fetched at the commit it
   names and checked against their SHA-256: Lean reproduces every vector's
   hash, keyed_hash, and derive_key output.
4. The Lean builds, and every theorem rests on Lean's standard axioms alone.
5. Every quotation of BLAKE3.md in the Lean files' comments appears in it,
   each `[...]` marking an omission.

Exits nonzero on the first difference.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import generate

# The vectors the appendix links, by the SHA-256 of the file at that commit
# (the same file as BLAKE3's repository holds today).
VECTORS_SHA256 = "dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624"


def fail(msg):
    sys.exit(f"check.py: {msg}")


def words(text):
    return [int(w, 16) for w in text.split()]


def appendix_traces(md):
    """The appendix's compressions, in order, with the conventions applied."""
    app = md[md.index("## Appendix: Test Values"):]
    examples = re.split(r"\n### ", app)[1:]
    out = []
    for ex in examples:
        title = ex.splitlines()[0].strip()
        block = re.search(r"```\n(.*?)```", ex, re.S).group(1)
        entries = re.split(r"\n\s*== COMPRESS: (.*?) ==\n", "\n" + block)
        hash_value = re.search(r"hash value:\s*\n\s*([0-9a-f]+)", block).group(1)
        carry = {}
        comps = []
        for label, body in zip(entries[1::2], entries[2::2]):
            body += "\n"      # the split takes the newline before the next entry
            fields = {}
            for name, value in re.findall(r"^ (h|m|t|flags|after round \d|compress output):[ \t]*\n((?:[ \t]+[0-9a-f][0-9a-f ]*\n)+)", body, re.M):
                fields[name] = value
            c = {"label": label}
            for k in ("m", "t", "flags"):
                if k in fields:
                    carry[k] = fields[k]
                if label == "PARENT" and k not in fields:
                    fail(f"the root's trace lacks its {k}")
            c["h"] = words(fields["h"])
            c["m"] = words(carry["m"])
            c["t"] = words(carry["t"])
            c["flags"] = int(carry["flags"].strip(), 16)
            c["rounds"] = [words(fields[f"after round {r}"]) for r in range(7) if f"after round {r}" in fields]
            c["out"] = words(fields["compress output"])
            comps.append(c)
        out.append({"title": title, "compressions": comps, "hash": hash_value, "text": ex})
    return out


def check_trace_consistency(traces):
    """The appendix's own statements, checked of its trace."""
    one, two = traces
    if "4-byte message\n\"IETF\"" not in one["text"].replace("  ", " "):
        fail("the first example's text names a message other than the 4-byte \"IETF\"")
    msg = b"IETF" + bytes(60)
    want_m = [int.from_bytes(msg[4 * i:4 * i + 4], "little") for i in range(16)]
    c0 = one["compressions"][0]
    if c0["m"] != want_m or c0["t"] != [0, 0]:
        fail("the first example's block or counter differs from \"IETF\" padded with zeros at counter 0")
    one["len"] = 4
    one["input_hex"] = msg[:4].hex()
    # Second example: chunks of 0xaa and 0xbb, key 0xcc.
    if "0xaa" not in two["text"] or "0xbb" not in two["text"] or "0xcc" not in two["text"]:
        fail("the second example's text names bytes other than 0xaa, 0xbb, and the key's 0xcc")
    comps = two["compressions"]
    for prev, cur in zip(comps, comps[1:]):
        if cur["label"].startswith("CHUNK") and not cur["label"].endswith("BLOCK  0") and cur["h"] != prev["out"]:
            fail(f"the trace's {cur['label']} starts from a value other than the previous block's output")
    two["len"] = 64
    two["input_hex"] = (b"\xaa" * 1024 + b"\xbb" * 1024).hex()
    two["key_hex"] = (b"\xcc" * 32).hex()
    root = comps[-1]
    if root["label"] != "PARENT" or root["m"] != comps[15]["out"] + comps[31]["out"]:
        fail("the root's message differs from the two chunks' chaining values")


def vectors(md):
    """The official test vectors the appendix links, at its pinned commit."""
    url = re.search(r"\[test vectors\]: (https://github.com/BLAKE3-team/BLAKE3/blob/[0-9a-f]+/test_vectors/test_vectors.json)", md).group(1)
    raw = url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")
    path = os.path.join(HERE, "test_vectors.json")
    if not os.path.exists(path):
        with urllib.request.urlopen(raw, timeout=60) as r:
            with open(path, "wb") as f:
                f.write(r.read())
    if hashlib.sha256(open(path, "rb").read()).hexdigest() != VECTORS_SHA256:
        fail(f"{path} differs from the file the appendix links")
    return path, url


def normal(text):
    """Text as compared: Markdown's list markers and emphasis marks dropped,
    `<sup>n</sup>` as `^n`, whitespace collapsed."""
    text = re.sub(r"^\s*\*\s+", "", text, flags=re.M).replace("**", "")
    return " ".join(re.sub(r"<sup>(\w+)</sup>", r"^\1", text).split())


def check_quotations(md):
    """Each quotation in a comment of the hand-written Lean is the
    document's text, `[...]` marking each omission."""
    doc = normal(md)
    count = 0
    for name in ("Blake3.lean", "Theorems.lean"):
        lean = open(os.path.join(HERE, name)).read()
        if generate.BEGIN in lean:
            i, j = lean.index(generate.BEGIN), lean.index(generate.END)
            lean = lean[:i] + lean[j:]
        for comment in re.findall(r"/-[-!](.*?)-/", lean, re.S):
            for quote in re.findall(r'"([^"]+)"', comment):
                for fragment in quote.split("[...]"):
                    fragment = normal(fragment).strip(" ,.:")
                    if fragment and fragment not in doc:
                        fail(f"{name} quotes text BLAKE3.md lacks: {fragment!r}")
                count += 1
    return count


def lake(*args):
    return subprocess.run(["lake", *args], cwd=HERE, capture_output=True, text=True)


def main():
    md_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "BLAKE3.md")
    md = open(md_path).read()
    # 1. The generated section.
    try:
        gen = generate.generate(md)
    except generate.Refused as e:
        fail(f"generate.py refused BLAKE3.md: {e}")
    lean = open(os.path.join(HERE, "Blake3.lean")).read()
    i, j = lean.index(generate.BEGIN), lean.index(generate.END) + len(generate.END) + 1
    if lean[i:j] != gen:
        fail("Blake3.lean's generated section differs from generate.py's translation of BLAKE3.md")
    print("sections 2.2-3.3: Blake3.lean's generated section is generate.py's translation of BLAKE3.md")
    # 2. The appendix.
    traces = appendix_traces(md)
    check_trace_consistency(traces)
    n = sum(len(t["compressions"]) for t in traces)
    print(f"appendix: {n} compressions extracted; the trace is consistent with itself and the text")
    fields = ("title", "compressions", "hash", "len", "input_hex")
    with open(os.path.join(HERE, "traces.json"), "w") as f:
        json.dump([{k: t[k] for k in fields} | {"key_hex": t.get("key_hex", "")} for t in traces], f, indent=1)
    # 3. The vectors.
    vpath, vurl = vectors(md)
    # 4. Lean: build, the theorems' axioms, then the tests.
    r = lake("build")
    if r.returncode:
        fail("lake build failed:\n" + r.stdout[-3000:] + r.stderr[-2000:])
    names = [t for f in ("Blake3.lean", "Theorems.lean")
             for t in re.findall(r"^theorem (\w+)", open(os.path.join(HERE, f)).read(), re.M)]
    probe = "import Theorems\n" + "".join(f"#print axioms Blake3.{t}\n" for t in names)
    with open(os.path.join(HERE, ".axioms.lean"), "w") as f:
        f.write(probe)
    r = lake("env", "lean", ".axioms.lean")
    os.remove(os.path.join(HERE, ".axioms.lean"))
    allowed = {"propext", "Classical.choice", "Quot.sound"}
    lines = [l for l in r.stdout.splitlines() if "axioms" in l]
    if len(lines) != len(names):
        fail(f"#print axioms reported {len(lines)} of {len(names)} theorems:\n" + r.stdout + r.stderr)
    for t, line in zip(names, lines):
        listed = re.search(r"depends on axioms: \[(.*)\]", line)
        used = {a.strip() for a in listed.group(1).split(",")} if listed else set()
        if not used <= allowed:
            fail(f"theorem {t} rests on {sorted(used - allowed)}")
    print(f"theorems: all {len(names)} rest on Lean's standard axioms alone")
    print(f"quotations: all {check_quotations(md)} in the Lean files' comments are BLAKE3.md's text")
    r = lake("env", "lean", "--run", "Tests.lean", "traces.json", "test_vectors.json")
    print(r.stdout, end="")
    if r.returncode:
        fail("Tests.lean failed:\n" + r.stderr[-3000:])
    print(f"check.py: Blake3.lean matches BLAKE3.md (vectors: {vurl})")


if __name__ == "__main__":
    main()
