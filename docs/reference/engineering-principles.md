# Engineering Principles Reference

A general-purpose checklist for code review and architecture decisions in Rust projects. Not every principle applies with equal force to every codebase -- several of the classic OO principles have little material weight in small, procedural Rust binaries, while carrying real weight in larger, multi-crate systems. Use judgment about which sections actually bite for the code under review; don't force a finding just to check a box against every principle.

Part A covers general software-engineering and Rust-language *design* principles. Part B covers the operational/tooling side of the Rust ecosystem -- practices around dependencies, runtime verification, error types, CI/CD, observability, and benchmarking.

---

# Part A -- Design Principles

## 1. Universal Software Engineering Principles

- **DRY (Don't Repeat Yourself)** -- extract repeated logic into a function, generic, or macro. Watch for the same parsing/validation/encoding logic reimplemented independently in more than one place; consolidate onto one shared implementation once a second real occurrence appears.
- **KISS (Keep It Simple, Stupid)** -- prefer simple, direct code over macros or generic gymnastics used to show off. When two designs solve the same problem, prefer the one that's easier to read cold, not the one that's more clever.
- **YAGNI (You Ain't Gonna Need It)** -- don't build for hypothetical future requirements; Rust's compiler makes it cheap to extend code later when a real need shows up. Resist abstracting for portability, configurability, or extensibility that no concrete, currently-planned use case requires.
- **Rule of Three** -- write it plain the first time, copy-paste the second time, abstract only on the third occurrence. A useful gut-check against premature abstraction that complements YAGNI.
- **Separation of Concerns (SoC)** -- decompose a program into distinct parts, each handling one concern; in Rust, primarily via the module system (`mod`). A module that handles both I/O and business logic, or both configuration loading and domain computation, is a SoC smell worth splitting.
- **Command-Query Separation (CQS)** -- a function either performs an action (mutates state, no meaningful return) or answers a question (returns data, no side effects), not both. Deliberately violating CQS in a performance-critical hot loop (to avoid an extra allocation or pass) is an acceptable, explicit trade-off -- not a default.
- **Boy Scout Rule** -- leave the code a little cleaner than you found it. Applies at both the single-file and whole-project scale.

## 2. SOLID Principles (Rust-Specific Notes)

- **S -- Single Responsibility.** A module/struct should have one reason to change. Rust: keep `mod`/`struct`/`trait` boundaries aligned with one responsibility each, for high cohesion. A module whose name describes one job but whose contents serve two unrelated ones (e.g. encoding logic mixed with unrelated numeric rounding) is a straightforward split candidate.
- **O -- Open/Closed.** Open for extension, closed for modification -- new behavior via new `trait` impls or generics, not by editing working code. Parameterizing an algorithm's constants (rather than hardcoding them) so a new variant becomes a new thin wrapper, not a change to the algorithm itself, is the idiomatic Rust shape of this principle.
- **L -- Liskov Substitution.** Any type implementing a trait must be substitutable wherever that trait is expected, without surprising callers. In codebases with few polymorphic type hierarchies, don't manufacture a finding where there's no real substitution relationship to violate. Rust note: since Rust has no classical inheritance, LSP shows up purely as "does every impl of this trait honor the trait's implied contract," not as a class hierarchy concern.
- **I -- Interface Segregation.** Don't force callers to depend on methods they don't use; prefer several small, focused traits over one large one. A large context struct passed wholesale into several functions that each touch only a subset of its fields is a mild ISP smell -- often an acceptable trade-off in a performance-critical hot loop to avoid parameter-list explosion, but worth a second look elsewhere.
- **D -- Dependency Inversion.** High-level code should depend on abstractions (`trait`s), not concrete low-level details; combine with dependency injection for decoupling. Introducing an abstraction trait for a dependency that has exactly one real implementation and no second implementation on the horizon is speculative and contradicts YAGNI -- revisit only when a second real implementation is actually needed.

## 3. Rust-Specific Design Philosophy

- **Composition over Inheritance.** Rust has no class inheritance at all -- it forces sharing behavior via struct composition and traits instead. Not a choice to make in Rust, a structural fact of the language.
- **Zero-Cost Abstractions.** Generics, monomorphization, and iterators compile down with no runtime overhead versus hand-written code -- don't sacrifice a clean abstraction for performance the compiler would have given you for free anyway. Before rejecting an abstraction on performance grounds, check whether it actually costs anything at the generated-code level, or only in perceived complexity.
- **Data/Behavior Separation.** Unlike classical OOP's "data and methods bundled in one class," idiomatic Rust keeps `struct`s as plain data and puts behavior in separate `impl`/`trait` blocks.
- **RAII (Resource Acquisition Is Initialization).** Rust's ownership/lifetime system plus `Drop` releases memory, file handles, and locks automatically at scope exit -- avoid manual resource-lifecycle management.
- **Correct Error Handling.** No bare `panic!`/`.unwrap()` in production code; recoverable errors return `Result<T, E>`, absence-of-value uses `Option<T>`, and `?` propagates errors upward. Production code that panics or exits abruptly on a condition that a caller could reasonably encounter (malformed input, a missing file) should instead surface a typed error.

  Bad -- panics the whole process on a condition callers will hit routinely:

  ```rust
  fn load_config(path: &str) -> Config {
      let text = std::fs::read_to_string(path).unwrap();
      toml::from_str(&text).unwrap()
  }
  ```

  Good -- caller decides how to handle a missing/malformed file:

  ```rust
  fn load_config(path: &str) -> Result<Config, ConfigError> {
      let text = std::fs::read_to_string(path)
          .map_err(|e| ConfigError::Read(path.into(), e))?;
      toml::from_str(&text).map_err(|e| ConfigError::Parse(path.into(), e))
  }
  ```

- **Make Illegal States Unrepresentable.** Use the type system (enums with associated data, newtypes) to eliminate whole classes of bugs at compile time instead of defending against them with runtime `if`/`else`. A newtype that wraps a value only after validating an invariant (e.g. "this slice is exactly one block long") makes that invariant a state a caller cannot even construct incorrectly, rather than a runtime check a future caller could forget to add.

  Bad -- nothing stops a caller from passing a slice of the wrong length; the check can be forgotten or duplicated inconsistently at each call site:

  ```rust
  fn digest_block(block: &[u8]) -> [u8; 32] {
      assert_eq!(block.len(), 64);
      // ...
  }
  ```

  Good -- constructing the type IS the validation; a wrong-length slice can never reach `digest_block` at all:

  ```rust
  struct Block64<'a>(&'a [u8]);

  impl<'a> Block64<'a> {
      fn new(slice: &'a [u8]) -> Result<Self, LengthError> {
          (slice.len() == 64).then(|| Self(slice)).ok_or(LengthError)
      }
  }

  fn digest_block(block: Block64) -> [u8; 32] { /* ... */ }
  ```

- **`unsafe` Minimization and Documentation.** Every `unsafe` block should be as small as possible -- ideally scoped to just the operation that requires it, not the surrounding logic -- and carry a comment stating the specific safety invariant the surrounding code upholds (alignment, initialization, bounds) that the compiler cannot verify on its own. This matters most around SIMD intrinsics and raw-pointer manipulation, where invariants are easy for a future editor to accidentally break while looking like a harmless refactor.

  Bad -- a wide unsafe block with no stated invariant; a future edit that shrinks `buf` below 16 elements compiles fine and reads out of bounds:

  ```rust
  unsafe fn load(buf: &[i32]) -> __m512i {
      let ptr = buf.as_ptr();
      _mm512_loadu_si512(ptr as *const _)
  }
  ```

  Good -- invariant is checked at the boundary, `unsafe` is scoped tightly, and the comment states exactly what the compiler can't verify:

  ```rust
  fn load(buf: &[i32]) -> __m512i {
      assert!(buf.len() >= 16, "load requires at least 16 i32 elements");
      // SAFETY: buf.len() >= 16 was just checked, so the load reads exactly
      // 16 valid i32s (64 bytes); _mm512_loadu_si512 has no alignment
      // requirement (unaligned load).
      unsafe { _mm512_loadu_si512(buf.as_ptr() as *const _) }
  }
  ```

- **Constant-Time Discipline for Cryptographic Code.** Code that handles secret or signature-verification-relevant data should not branch or index in ways whose timing depends on the secret value, since that creates a timing side-channel. The general rule: never hand-roll comparison or arithmetic on verification-path secret material -- prefer an audited crate over a bespoke implementation, even when the bespoke version is functionally correct, because "correct" and "constant-time" are different properties and the latter is much harder to verify by inspection.

  Bad -- `==` on byte slices short-circuits at the first mismatching byte, so comparison time leaks how many leading bytes were guessed correctly:

  ```rust
  fn verify_mac(expected: &[u8], actual: &[u8]) -> bool {
      expected == actual
  }
  ```

  Good -- constant-time comparison from an audited crate; every byte is examined regardless of where the first mismatch occurs:

  ```rust
  use subtle::ConstantTimeEq;

  fn verify_mac(expected: &[u8], actual: &[u8]) -> bool {
      expected.ct_eq(actual).into()
  }
  ```

## 4. Classic Package/Architecture Principles (Beyond SOLID)

- **LoD (Law of Demeter / Principle of Least Knowledge)** -- an object should know as little as possible about other objects' internals. Rust: keep `pub` surface minimal, hide implementation details behind module boundaries. Whether a helper becomes `pub(crate)` or stays module-private is exactly a LoD/encapsulation call, not just a compile-error workaround.
- **CRP (Common Reuse Principle)** -- classes/components in one package should be reused together, or not at all; if you depend on part of a package, you should reasonably depend on all of it.
- **CCP (Common Closure Principle)** -- things that change together should live together in the same package; this is SRP applied at the package/module level rather than the single-type level.
- **SAP (Stable Abstractions Principle)** -- a package's abstractness should be proportional to its stability; the most stable packages should be the most abstract (in Rust, the most trait-heavy).
- **SDP (Stable Dependencies Principle)** -- depend in the direction of stability; a stable package should never depend on a less-stable one.

These four (CRP/CCP/SAP/SDP) are primarily aimed at large, multi-package systems with many consumers and independent release cadences. In a single-binary crate with no external consumers of its internal modules, there's often no "package" boundary in the relevant sense for these to bind on -- CCP still has some genuine echo in SRP-driven module splits (things that change for the same reason landing in the same file), but usually doesn't add anything beyond what SRP already covers at small scale.

## 5. Unix Philosophy

- **Do one thing well** -- a program should do one thing and do it well.
- **Work together** -- programs should compose via standard interfaces (stdin/stdout, or in Rust, standard traits).
- **Favor simplicity over complexity.**
- **Robustness principle** -- be transparent (easy to understand) and handle unexpected input gracefully; in Rust this shows up as exhaustive `match` over enums rather than falling through to a default case.

For a CLI tool, this means each subcommand should be meant to do one legible thing, and subcommands should be composable in the Unix sense -- piping one command's stdout into another tool should work cleanly, which in practice means reserving stderr for metadata/diagnostics and keeping stdout machine-readable.

## 6. Rust API Design Guidelines

- **Parse, don't validate.** Don't re-validate the same data repeatedly at runtime -- parse it once into a newtype whose existence proves validity. Constructing the newtype *is* the validation, and it can never be "revalidated incorrectly" downstream because there's no raw, unvalidated form left to re-check.
- **Explicit over Implicit.** Allocation (`.clone()`), conversion (`.into()`), control flow, and lifetimes should be visible in the code, not happening invisibly in the background the way a scripting language might hide them.
- **Ownership-Driven API Design.** Use the ownership/borrowing system itself to communicate intent: consuming `self` signals a single-use operation, `&self` signals a read-only operation, `&mut self` signals exclusive mutation.
- **Fail-Fast & Compile-Time Safety.** Anything the compiler can catch should never be deferred to a runtime check. Fixed-size array parameters (so a length mismatch is a compile error, not a runtime one) and schema-driven config parsing (turning a malformed config file from a silent-corruption runtime bug into a parse error with a specific message) are both instances of this.
- **Documentation as a First-Class Citizen.** Write thorough `///` doc comments and keep examples aligned with the actual implementation during review. Document input contracts, byte order, and failure behavior explicitly for hand-implemented, non-standard algorithms.

---

# Part B -- Rust Ecosystem Operational Practices

Part A covers design-time principles (how code and types are shaped). Part B covers the operational/tooling side: dependency governance, production runtime verification, error type conventions, CI/CD, observability, and performance measurement.

## 7. Dependency & Supply-Chain Governance

- **`cargo audit`** -- scan `Cargo.lock` against the RustSec Advisory Database for known vulnerabilities in dependencies. Cheap to run, should be part of any pre-release check.
- **`cargo deny`** -- broader than `audit`: also enforces license allow-lists, bans duplicate dependency versions, and can block specific crates/sources outright.
- **`Cargo.lock` committed to version control** -- mandatory for a binary crate (as opposed to a library, where it's optional/discouraged). Guarantees reproducible builds; without it, `cargo build` on a fresh checkout can silently pull newer, unvetted dependency versions.
- **MSRV (Minimum Supported Rust Version) policy** -- state the minimum toolchain version the project builds against, and verify it in CI (`cargo +<msrv> check`). Prevents accidentally depending on a language feature or stdlib API newer than what's documented.

Choosing an audited crate for security-sensitive functionality (rather than hand-implementing it) is only as good as the mechanism that keeps verifying the dependency stays clean over time -- the choice itself is a point-in-time judgment, not an ongoing guarantee, without `cargo audit`/`cargo deny` wired into a recurring check.

## 8. Production Runtime Verification

- **`mtsc verify`** -- retain the self-contained SOFTWARE ID pipeline and encoding round-trip checks in the production CLI.
- **`HashEngine::self_check`** -- retain startup checks against the production scalar implementation for supported CPU backends; never execute unsupported instruction sets.
- **Search hit verification** -- recompute the full SOFTWARE ID from each hit's actual serial/model/size/identity/bus before reporting it.

These are production safeguards, not a separate automated test suite. The project contains only production library/CLI code; standalone test and benchmark programs are not part of the current tooling.

## 9. Error-Type Design Idioms

- **`thiserror` for library-shaped error types** -- derives `std::error::Error` and `Display` for an enum, keeping each error variant a well-typed, matchable value. Appropriate when callers (including your own future code) need to distinguish error variants programmatically.
- **`anyhow` for application-shaped error handling** -- a single dynamic `anyhow::Error` type for the "top" of a binary's call stack (typically `main`), where the caller just wants to propagate-and-report, not match on variants. Common pattern: internal modules return `thiserror`-based typed errors; `main` (or a thin CLI-command layer) collects them into `anyhow::Result<()>` for a single exit point.
- **Error message quality as a contract, not an afterthought** -- an error a user will actually read (malformed config, invalid input) should say what was wrong and, where possible, what a valid value looks like -- not just `Err(e)`.

  Bad -- technically correct, tells the user nothing actionable:

  ```rust
  return Err(anyhow!("invalid input"));
  ```

  Good -- states what was wrong and what a valid value looks like:

  ```rust
  return Err(anyhow!(
      "disk size '{raw}' is not a valid size: expected a number followed by \
       a unit (g/m/k/b), e.g. '100g' or '512m'"
  ));
  ```

This section is about *which* error-handling crate/pattern to reach for once it's already decided that errors must be typed and not `panic!`/`.unwrap()` in production code (see Part A §3). For a CLI (as opposed to a library consumed by other Rust code), an `anyhow`-at-the-top / typed-errors-in-modules split is the standard shape -- worth adopting deliberately rather than each module inventing its own ad hoc error enum or string-based error.

## 10. CI/CD & Release Discipline

- **CI matrix** -- compile all six Linux/Windows/macOS × x86_64/aarch64 targets, run `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`, and package artifacts. Distributed binaries use portable CPU settings, not `target-cpu=native`.
- **Semantic Versioning (SemVer)** -- for a CLI tool, SemVer applies primarily to *behavior/output stability* (flag names, output format on stdout that other tools might pipe from) rather than a Rust API surface, but the discipline of "does this change break an existing consumer" still applies.
- **`cargo semver-checks`** -- automated SemVer-compliance checking; more relevant if/when any part of a codebase is exposed as a library crate rather than only a binary.
- **Changelog maintenance (`CHANGELOG.md`, Keep a Changelog format)** -- especially valuable when command-line flags are the actual "API" users depend on; a changelog documents when a flag's default or meaning changed.

A set of check commands documented in a README or contributor guide is only as reliable as each contributor's memory to run them before committing -- the same checks wired into an actual CI pipeline remove that dependency on memory entirely.

## 11. Observability & Diagnostic Output

- **Structured, leveled logging (`tracing` or `log` + `env_logger`)** -- distinguishes trace/debug/info/warn/error, filterable at runtime via an env var, instead of unconditional `eprintln!`. Enables a `--verbose`/`RUST_LOG` knob without scattering `if verbose { eprintln! }` checks through hot paths.
- **stdout/stderr separation as a stable contract** -- machine-readable output goes to stdout, diagnostics/metadata go to stderr, so piping a command's output into another tool works cleanly. Worth stating as a general principle for any new subcommand, rather than re-deciding the split case by case.
- **Progress reporting in long-running loops** -- keep progress-reporting overhead (formatting, syscalls) off the hot path; batch or throttle updates rather than emitting one per iteration.

For a short-lived CLI invocation rather than a long-running service, most of the "observability" toolbox (metrics export, distributed tracing) doesn't apply. The stdout/stderr contract and throttled progress reporting are usually the parts that genuinely matter; introducing a full `tracing` subscriber for a tool that runs for seconds-to-minutes and exits can be over-engineering relative to YAGNI (Part A §1).

## 12. Performance Measurement Discipline

- **Record measurement context** -- CPU, OS, compiler, worker count, workload, warm-up, sample duration, and variability are necessary to interpret a throughput number.
- **Distinguish workloads** -- hash-kernel and serial-preparation rates are not full search throughput or expected collision time. The [historical measurements](../benchmarks/README.md) preserve these distinctions; the standalone benchmark program is no longer included.
- **`perf`/`cargo flamegraph` for profiling before optimizing** -- avoid speculative micro-optimizations; profile to confirm the hot path before spending effort on it. This is the performance-engineering analog of YAGNI: don't optimize what profiling hasn't shown to be the bottleneck.

Production startup calibration chooses among supported backends at the requested concurrency; it is a short runtime heuristic, not a guarantee of the best end-to-end throughput under every load.

## Summary Table (Part B)

| Area | Tooling |
|---|---|
| Supply chain | `cargo audit`, `cargo deny`, committed `Cargo.lock`, MSRV |
| Runtime verification | `mtsc verify`, `HashEngine::self_check`, full-SID hit verification |
| Error types | `thiserror` (modules) + `anyhow` (top level) |
| CI/CD | six-platform builds, Clippy, formatting checks, artifact packaging |
| Observability | `tracing`/leveled logs, stdout/stderr contract |
| Performance | contextualized historical measurements, profile-before-optimize |
