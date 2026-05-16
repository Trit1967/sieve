# Adding patterns to the wordlist

`crates/sieve-core/src/data/jailbreaks.txt` ships with the crate. To
add patterns:

1. Open `crates/sieve-core/src/data/jailbreaks.txt`.
2. Add one pattern per line. ASCII-fold + lowercase normalization is
   applied at load time, so duplicates that differ only by case are
   automatically deduplicated.
3. Cite the source in `crates/sieve-core/src/data/provenance.txt`.
4. Run `cargo test --test corpus -- --include-ignored` to verify the
   FPR doesn't regress on the curated benign set in `benign.txt`.

The v0.2 sieve-corpus repository will host the larger ~5,000-pattern
external merge; until then, please keep additions to the in-tree
wordlist conservative (under 50 lines per PR) so reviewers can audit
by hand.
