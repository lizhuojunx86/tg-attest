# Mutation testing

Line coverage is not a useful signal for this library. All three fail-open defects found in the
first review were sitting on lines the test suite executed — the tests ran the code, watched it
return the wrong answer, and passed anyway. The question worth asking is different:

> If this code were wrong, would a test fail?

Mutation testing answers it by breaking the code on purpose and checking whether the suite
notices.

## How to run it

```bash
pip install -e ".[tsa,dev]" mutmut
mutmut run --max-children 8      # ~10 min
mutmut results
mutmut show <mutant-id>
```

Configuration is in `pyproject.toml` under `[tool.mutmut]`.

### One setup trap worth knowing about

The first three runs reported **0 killed** out of ~1250 mutants. That number is not a finding,
it is a broken harness — and it is worth stating plainly because the failure mode is quiet.

`pip install -e .` writes a `.pth` file containing one absolute path to `<repo>/src`. mutmut
copies the source into `mutants/` and runs pytest there, but `import tg_attest` still resolved
through that `.pth` back to the *original* tree. Every mutant "survived" because no mutant was
ever loaded.

`tests/conftest.py` now prepends its sibling `src/` to `sys.path` before any `tg_attest` import,
which makes the mutants copy win. If a mutation report ever comes back with a suspiciously
round number — 0 killed, or 100% killed — check the harness before believing it.

## Results

Latest full run, 1350 mutants across all five modules:

| Outcome | Count | Previous round |
|---|---|---|
| Killed | 953 | 846 |
| Survived | 152 | 164 |
| Timeout (killed by hang) | 2 | 9 |
| No covering test | 235 | 235 |

Kill rate over mutants that had a covering test: **955 / 1107 ≈ 86%**.

That number on its own is not the point. What matters is *which* mutants survived, so the rest
of this document goes through them.

## What the survivors were, before they were fixed

The run found four mutations on the certificate-chain path that the entire suite failed to
notice, and every one of them pointed the same direction — toward accepting evidence that
should be rejected:

| Mutation | What it means in plain terms |
|---|---|
| `if not _valid_at(issuer, at_time): return False` → `return True` | An issuing CA that was expired at genTime makes the chain **valid** |
| `if not _verify_sig(issuer, cur): return False` → `return True` | A certificate whose signature does not verify makes the chain **valid** |
| loop-exhausted `return False` → `return True` | A chain too long to walk is treated as **valid** |
| `extn_id == EKU and critical` → `or` | A TSA certificate whose EKU is not critical passes the critical check |

The second one is the one to look at. It means a forged intermediate CA — same subject name,
attacker's key — would have been accepted. The reason no test caught it is specific and
instructive: the existing "wrong CA is rejected" test used an *unrelated* self-signed root, so
the issuer lookup failed and the function returned early. The signature-verification branch was
never reached by any test, in either direction.

You cannot construct these cases with real timestamps. No TSA will issue a certificate with a
non-critical EKU, and FreeTSA's root validity window strictly contains its leaf's, so there is no
instant at which the leaf is valid and the issuer is not. `tests/synthpki.py` builds a small
synthetic PKI for exactly these branches; the certificates never leave the test process.

All four are now killed by `tests/test_chain_synthetic.py`.

The same run also flagged something in the write path that is arguably more important, because
no amount of cryptography can compensate for it:

| Mutation | What it means |
|---|---|
| `actor=actor` → `actor=None` in `Ledger.append` | The record drops the actor — and the chain stays perfectly self-consistent |

`record_hash` is computed *after* the fields are assigned, so a record that silently lost a field
hashes correctly, links correctly, seals correctly, and gets timestamped correctly.
`led.verify()` returns `[]`. The verifier prints 通过. This is the worst failure this library can
have: cryptographically impeccable proof of a record whose content went missing.
`tests/test_record_fidelity.py` now pins every field, and includes one test that asserts the
weakness itself so nobody mistakes integrity for correctness.

## Surviving mutants, classified

164 survive. None of them flips a verdict from fail to pass. Grouped by why:

### Equivalent — the mutation cannot change behaviour

| Mutant | Why it cannot matter |
|---|---|
| `VerifyResult(ok=False)` → `ok=True` / `ok=None` (4×) | `conclude()` overwrites `ok` on every return path. The initial value is dead — which is *evidence the structural fix worked*. Before `REQUIRED_CHECKS`, this mutant would have been lethal. |
| `_load_anchors`: `on = False` → `True`, `keepends=False`, `buf.append(None)` (6×) | `buf` is reset at each `BEGIN CERTIFICATE`; `buf[1:-1]` discards the boundary lines; base64 ignores line breaks. Verified by reading, then confirmed with a multi-certificate PEM test. |
| `canonical_bytes`: `ensure_ascii=None`, `.encode("UTF-8")` (2×) | `None` is falsy; codec names are case-insensitive. |
| `_chain_ok`: `seen.add(issuer.sha256)` → `seen.add(None)` | `range(8)` already bounds termination and the walk never backtracks, so `seen` only short-circuits. Same result, more iterations. |
| `_chain_ok`: `range(8)` → `range(9)` | Real chains here are 2 deep. |
| `_chain_ok`: `"maybe"` / `"yes"` string mutations (4×) | Guarded by an identity comparison against a trust anchor; the `self_signed` value cannot alone admit anything. |
| `seal_epoch` / `disclose`: `end_seq + 1` → `+ 2` (2×) | The API only ever seals through the tail, so the extra index is always past the end and Python slicing absorbs it. Latent if partial sealing is ever added — noted here rather than fixed, because a test asserting current behaviour would forbid the future feature. |

### Message text — asserted by meaning, not by spelling

61 mutants change error-message and metadata strings (`"XX…XX"` wrapping, case flips). Tests
assert on meaningful substrings — `"信任根"`, `"找不到"`, `"没有解析出任何证书"` — rather than exact
text, which is deliberate: pinning full message strings makes every wording improvement a test
failure without catching a single real defect.

`export_bundle`'s `_verify` block is the exception. It is the auditor-facing contract, so
`test_verify_block_is_the_auditor_facing_contract` pins its structure and the trust-root warning.

### Fail-closed — the mutation makes things stricter, or errors out

| Mutant | Result |
|---|---|
| `r.errors.append(None)` (4×) | `errors` non-empty ⇒ `ok=False`. Verdict unchanged; only the printed text degrades. |
| `r.conclude(TOKEN_REQUIRED_CHECKS)` → `conclude(None)` (2×) | `TypeError` inside the `try` ⇒ recorded as an error ⇒ fails. |
| `next(…, None)` → `next(…)` for `message_digest` | `StopIteration` ⇒ caught ⇒ fails. |
| `problems.append(None)` in `Ledger.verify` (2×) | `problems` non-empty ⇒ tampering still reported. |
| `verify_bundle`: `if not tr.ok and not r.errors` → `and r.errors` | Defence in depth. The sub-result's failure already propagates through `checks`/`missing`. |

### Cosmetic — formatting and serialisation

| Mutant | Result |
|---|---|
| `json.dump`: `indent=2` → `3`, `ensure_ascii=False` → `True` (5×) | The verifier re-canonicalises before hashing, so serialisation style cannot affect a verdict. |
| `open(…, encoding="utf-8")` → `encoding=None` (3×) | Would break on a non-UTF-8 locale. Genuine portability concern, not a verification one; the explicit encoding stays. |
| `_len` / `der_int` / `der_oid` byte-encoding mutants (23×) | Covered indirectly — `tests/test_tsq.py` compares the whole request byte-for-byte against `openssl ts -query`, which kills any mutation that changes the output. These survivors are mutations that produce *identical* bytes for the inputs under test. |

## The 235 mutants with no covering test

Broken down by function, with what each one actually means. The headline number is misleading in
two different directions, so it needs unpacking rather than quoting.

| Function | Count | Status |
|---|---|---|
| `cli.main` | 99 | **Covered — mutmut cannot see it.** See below. |
| `anchor.anchor_hash` | 90 | Network path. Accepted. |
| `AnchorQueue.flush` | 27 | Network path. Accepted. |
| `__getattr__` / `__dir__` | 9 | **Covered — mutmut cannot see it.** |
| `Ledger.evidence_index` | 6 | **Was a genuine hole. Now closed.** |
| `AnchorQueue.__init__` / `enqueue` | 4 | Trivial assignment; exercised indirectly. |

### The 108 that are a measurement artifact, not a hole

`cli.main` and the package `__getattr__` are tested — thoroughly, in `test_cli_output.py` (33
tests) and `test_zero_deps.py`. But those tests drive the code through `subprocess`, in a
separate interpreter. mutmut attributes tests to mutants using coverage collected inside the
pytest process, so anything executed across a process boundary registers as covering nothing.

This is worth stating plainly because the raw number invites exactly the wrong conclusion. The
tests were verified to bite by mutating the source by hand and re-running them:

| Hand-applied mutation | Result |
|---|---|
| verdict word inverted (prints 通过 when failing) | killed |
| `✗` rendered as `✓` | killed |
| `missing` entries not displayed | killed |
| conclusion line printed on failure | killed |
| exit code hardcoded to 0 | killed |

Five out of five. The subprocess boundary is a limitation of the measurement, and using
in-process invocation just to satisfy the tool would test something other than what users run.

### The 121 that are deliberately out of scope

`anchor_hash` and `AnchorQueue.flush` are network I/O. They are covered by the `-m network`
suite, which is deselected during mutation runs — a TSA outage mid-run would silently mark
mutants as killed for the wrong reason, which is worse than not measuring them. They run nightly
against all three live TSAs instead.

### The 6 that were real

`Ledger.evidence_index()` had no tests at all. It is the primitive the ReplayGate layer is meant
to build on — group evidence by `source_id`, recompute today's hash, find every past decision
whose basis has since been revised. Now covered by five tests in `test_record_fidelity.py`,
including one that walks the actual revision-detection use case.

## Where this leaves the verification path

The original goal was no surviving mutants on `verify.py`'s verification path. The honest
result:

- **No surviving mutant changes a verdict from fail to pass.** That property holds.
- Survivors on that path are message strings, provably equivalent mutations, and fail-closed
  degradations. Each is listed above with a reason.
- "Zero survivors" is not achievable without pinning exact error text, which trades real
  robustness for a number.

Re-run mutation testing after any change to `verify.py` or `record.py`. It is not part of CI —
ten minutes per run is too slow for every push — so it is a release gate, run by hand, with
results recorded here.
