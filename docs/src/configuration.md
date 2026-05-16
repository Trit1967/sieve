# Configuration

The `Scanner::default()` factory builds with sensible defaults for
every detector. Use `Scanner::builder()` to customize:

```rust
use sieve_core::{
    Scanner, UnicodeOpts, PatternOpts, EncodingOpts, HeuristicOpts, ContextOpts,
};

let scanner = Scanner::builder()
    .with_unicode(UnicodeOpts {
        strip_zero_width: true,
        strip_unicode_tags: true,
        apply_nfkc: true,
        apply_homoglyphs: true,
    })
    .with_patterns(PatternOpts {
        case_insensitive: true,
        normalize_whitespace: true,
        strip_punctuation: true,
    })
    .with_encoding(EncodingOpts {
        detect_base64: true,
        detect_hex: true,
        detect_rot13: true,
        min_segment_len: 20,
        max_recursion_depth: 2,
    })
    .with_heuristics(HeuristicOpts {
        instruction_density_threshold: 0.4,
        script_switch_max_scripts: 1,
        entropy_min_chars: 200,
        entropy_threshold: 2.5,
    })
    .with_context(ContextOpts {
        min_keyword_overlap: 2,
        max_instructions: 64,
    })
    .with_canary(true)
    .build()
    .expect("scanner builds");
```

Disable a detector entirely:

```rust
let s = Scanner::builder().without_patterns().without_encoding().build()?;
```

`without_patterns` also disables the encoding scanner's
post-decode re-scan (the encoding scanner needs the pattern scanner to
ask "is this decoded text malicious?").
