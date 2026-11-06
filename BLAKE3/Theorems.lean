import Blake3

/-! # Properties the specification states, proved of `Blake3.lean`

Section 4.3.2 describes the tree's shape by rules; `Blake3.lean` computes it: the left subtree of
`n ≥ 2` chunks holds `leftCount n`, the largest power of 2 below `n`. These theorems show that
number satisfies the rules and is the only one that does, so the definition and the prose agree.
Lean's kernel checks every proof. -/

namespace Blake3

/-- "Otherwise, the chunks are assembled with parent nodes, each parent node having exactly two
children": both subtrees of `n ≥ 2` chunks are nonempty. -/
theorem split_nonempty (n : Nat) (h : 2 ≤ n) : 0 < leftCount n ∧ 0 < n - leftCount n :=
  ⟨leftCount_pos n, by have := leftCount_lt n h; omega⟩

/-- "Left subtrees are full, that is, each left subtree is a complete binary tree, with all its
chunks at the same depth, and a number of chunks that is a power of 2." -/
theorem left_power_of_two (n : Nat) : ∃ k, leftCount n = 2 ^ k := ⟨_, rfl⟩

/-- "Left subtrees are big, that is, each left subtree contains a number of chunks greater than or
equal to the number of chunks in its sibling right subtree." -/
theorem left_big (n : Nat) (h : 2 ≤ n) : n - leftCount n ≤ leftCount n := by
  have := Nat.lt_log2_self (n := n - 1)
  rw [Nat.pow_succ] at this
  unfold leftCount; omega

/-- The rules determine the split: a power of 2 below `n` that is at least the rest is
`leftCount n`. -/
theorem split_unique (n k : Nat) (h : 2 ≤ n) (hlt : 2 ^ k < n) (hbig : n - 2 ^ k ≤ 2 ^ k) :
    2 ^ k = leftCount n := by
  have lo : k ≤ (n - 1).log2 := (Nat.le_log2 (by omega)).2 (by omega)
  have hi : (n - 1).log2 < k + 1 := (Nat.log2_lt (by omega)).2 (by rw [Nat.pow_succ]; omega)
  unfold leftCount
  rw [show (n - 1).log2 = k by omega]

/-- A full subtree stays full: `2^(k+1)` chunks split into two subtrees of `2^k`, so every left
subtree is complete, "with all its chunks at the same depth". -/
theorem full_splits_in_half (k : Nat) : leftCount (2 ^ (k + 1)) = 2 ^ k := by
  have := Nat.two_pow_pos k
  exact (split_unique (2 ^ (k + 1)) k (by rw [Nat.pow_succ]; omega)
    (by rw [Nat.pow_succ]; omega) (by rw [Nat.pow_succ]; omega)).symm

end Blake3
