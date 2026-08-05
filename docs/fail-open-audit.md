# Fail-open audit

Every `except`, every `if/else` default branch, and every `.get(key, default)` in
`src/tg_attest/`, with one question asked of each: **when this path is taken, does the
outcome get stricter or looser?**

The audit exists because the first three defects found in this library were all the same
shape — a failure happening *before* a check meant the check never ran, and the verdict only
looked at checks that did run. Patching them one at a time would have been treating symptoms.

Verdicts:

- **fail-closed** — taking this path makes the result more likely to be rejected. Correct.
- **fail-open** — taking this path makes the result more likely to be accepted. Fixed unless noted.
- **neutral** — display, logging, or a path that cannot influence a verdict.

---

## verify.py — the verification path

| Location | Construct | Behaviour when taken | Verdict | Status |
|---|---|---|---|---|
| `VerifyResult.conclude` | `all(checks.values())` over a runtime dict | Fewer checks ⇒ more likely to pass; `all({})` is `True` | **fail-open** | **Fixed** — replaced by static `TOKEN_REQUIRED_CHECKS` / `BUNDLE_REQUIRED_CHECKS`; a missing entry is now a failure. `test_required_checks.py` |
| `VerifyResult.conclude` | `errors` ignored in the verdict | Exception mid-parse ⇒ checks that ran all `True` ⇒ pass | **fail-open** | **Fixed** — non-empty `errors` forces `ok=False` |
| `verify_token` step 6 | `ca_bundle is None` wrote `checks["证书链校验"] = "已跳过…"` | Fabricated a record of a check that never ran | **fail-open (cosmetic)** | **Fixed** — now absent from `checks` and reported in `missing` |
| `verify_token` step 6 | `_load_anchors` returning `[]` | Empty PEM ⇒ chain check runs against zero anchors | fail-closed (returns `False`) | **Improved** — now an explicit error naming the real cause |
| `verify_token` step 5 | `_HASH.get(algo, hashes.SHA256)` | Unknown algorithm silently treated as SHA-256 | **fail-open** | **Fixed** — unknown algorithm returns `False` |
| `verify_token` step 5 | `except ValueError: sig_algo = digest_algo` | RFC 5652 §5.3 fallback for unbound-hash signature algorithms | fail-closed (signature still must verify) | Kept — required for DigiCert/Sectigo |
| `_find_signer` | `next(…, certs[0] if certs else None)` | `sid` matching nothing ⇒ verify against the first cert instead | **fail-open** | **Fixed** — no fallback; returns `None` ⇒ error |
| `_find_signer` | serial-only comparison | Serials are unique per issuer only | **fail-open** | **Fixed** — compares issuer **and** serial |
| `_verify_sig` | `except Exception: return False` | Any crypto error ⇒ signature invalid | fail-closed | Kept |
| `_verify_sig` | `else: return False` for non-RSA/EC keys | Ed25519 etc. rejected | fail-closed | Kept (compatibility gap, documented) |
| `_eku_status` | `eku` absent ⇒ `[]` | No EKU ⇒ check `False` | fail-closed | Kept |
| `verify_token` step 4 | `next(…, None)` for `message_digest` | Missing attribute ⇒ `md is None` ⇒ check `False` | fail-closed | Kept |
| `verify_token` | `certs = […] if sd["certificates"] else []` | No certs ⇒ signer `None` ⇒ error | fail-closed | Kept |
| `verify_token` / `verify_bundle` | bare `except Exception` | Records the error; `conclude` then fails | fail-closed | Kept |
| `_chain_ok` | leaf validity not checked | genTime outside signer cert window ⇒ accepted | **fail-open** | **Fixed** — `_valid_at(leaf)` before the loop |
| `_chain_ok` | `issuer is None or issuer.sha256 in seen` | Unknown or repeated issuer ⇒ reject | fail-closed | Kept |
| `_chain_ok` | `if not _valid_at(issuer)` | Issuer invalid at genTime ⇒ reject | fail-closed | Kept — **was untested**, now `test_issuer_expired_at_gentime_is_rejected` |
| `_chain_ok` | `if not _verify_sig(issuer…)` | Issuer signature invalid ⇒ reject | fail-closed | Kept — **was untested**, now `test_forged_issuer_with_matching_subject_is_rejected` |
| `_chain_ok` | `for _ in range(8)` then `return False` | Chain deeper than 8 ⇒ reject | fail-closed | Kept — **was untested**, now `test_chain_deeper_than_the_limit_is_rejected` |
| `verify_bundle` | `bundle.get("tsa_token")` falsy | No token ⇒ error ⇒ fail | fail-closed | Kept |
| `verify_bundle` | `if not tr.ok and not r.errors` | Belt-and-braces inheritance of the sub-result | fail-closed | Kept (defence in depth; unreachable in practice) |
| `export_bundle` | `b["epoch"].get("tsa_token")` ⇒ `None` | Silently exported a bundle that can never verify | **fail-open (usability)** | **Fixed** — raises unless `allow_unanchored=True` |
| `export_bundle` | `json.dump(…, default=str)` | Unserialisable values silently stringified ⇒ hash mismatch months later | **fail-open (silent corruption)** | **Fixed** — removed; now raises `TypeError` |

## record.py — the write path

| Location | Construct | Behaviour when taken | Verdict | Status |
|---|---|---|---|---|
| `_reject_floats` | recursive type check | Any float anywhere ⇒ `TypeError` | fail-closed | Kept |
| `canonical_bytes` | `sort_keys` / `separators` / `ensure_ascii` fixed | Deterministic bytes | neutral | Kept |
| `merkle_root` | `if not hashes: return GENESIS` | Empty span ⇒ sentinel constant, not an error | **borderline** | Kept — `seal_epoch` refuses empty spans and `verify` rejects inverted ranges, so the sentinel is unreachable from the API |
| `verify_inclusion` | `_node(sib, cur) if side == "L" else …` | Any non-`"L"` value silently meant "right" | **fail-open (latent)** | **Fixed** — `side not in ("L","R")` ⇒ `False` |
| `inclusion_proof` | `if not 0 <= index < len` | Out of range ⇒ `IndexError` | fail-closed | Kept |
| `Ledger.verify` | epoch loop had no span checks | Gaps between epochs left records covered by no Merkle root | **fail-open** | **Fixed** — contiguity, inversion, and out-of-range checks added |
| `Ledger.verify` | returns a list rather than raising | Audit wants every violation, not the first | neutral (by design) | Kept |
| `Ledger.seal_epoch` | `if end < start: raise` | Empty epoch refused | fail-closed | Kept |
| `Ledger.disclose` | `next(…, None)` then `raise` | Unsealed record ⇒ `ValueError` | fail-closed | Kept |
| `Ledger.verify_disclosure` | no exception handling | Malformed bundle raised instead of returning `False` | **borderline** | **Fixed** — returns `False`; caller's `if` now behaves |
| `Ledger.verify_disclosure` | checks structure only, never the timestamp | `True` does not mean "admissible" | **fail-open (naming)** | **Documented** — docstring now states it outright; `verify_bundle` is the real one |
| `Ledger.append` | `labels or {}`, `decided_at or now_iso()` | Falsy ⇒ default | neutral | Kept |
| `EvidenceRef.of` | `observed_at or now_iso()` | Falsy ⇒ now | neutral | Kept |

## anchor.py — the anchoring path

| Location | Construct | Behaviour when taken | Verdict | Status |
|---|---|---|---|---|
| `anchor_hash` | nonce `= sha256(digest + b"nonce")[:8]` | Derived from the digest, never checked ⇒ zero replay protection | **fail-open** | **Fixed** — `secrets.randbits(64)` + echo verification |
| `anchor_hash` | returned token never inspected | A token stamping a *different* digest was stored silently | **fail-open** | **Fixed** — `_verify_at_write` checks imprint + nonce when `[tsa]` is present |
| `_verify_at_write` | `except ImportError: return None, None` | No `[tsa]` ⇒ skipped | **accepted fail-open** | By design — soft dependency; recorded as `verified_at_write=None`, never as `True` |
| `_verify_at_write` | `except Exception: return False` | Unparseable token ⇒ anchor unusable | fail-closed | Kept |
| `Anchor.ok` | `verified_at_write is not False` | `None` (not checked) passes; `False` (checked, mismatched) blocks | fail-closed | Kept — `is not False` is deliberate, not a truthiness test |
| `_read_tlv` | `buf[i:i+n]` without bounds check | Truncated DER silently returned short | **fail-open** | **Fixed** — raises on truncation, rejects indefinite length |
| `parse_tsr` | everything after PKIStatusInfo taken as the token | Trailing garbage stored as a token | **fail-open** | **Fixed** — token must be one well-formed SEQUENCE with no trailing bytes |
| `parse_tsr` | `PKI_STATUS.get(status, f"unknown({status})")` | Unknown status ⇒ not in the success set | fail-closed | Kept |
| `anchor_hash` | `except Exception` ⇒ error `Anchor` | TSA unreachable must not block the decision path | **accepted fail-open (availability)** | By design — `ok` is `False`; monitor `AnchorQueue.pending` |
| `AnchorQueue.flush` | returns `None` when all TSAs fail | Queue retained for retry | fail-closed | Kept |
| `AnchorQueue.flush` | stops at the first success | One signature, not N | neutral (cost decision) | Documented in threat-model.md |

## cli.py / \_\_init\_\_.py

| Location | Construct | Behaviour when taken | Verdict | Status |
|---|---|---|---|---|
| `cli.main` | `return 0 if r.ok else 1` | Anything short of a full pass exits non-zero | fail-closed | Kept |
| `cli.main` | uncaught exception on malformed JSON | Traceback, exit code 1 | fail-closed | Kept |
| `cli.main` | `rec['actor'].get('id')` | Missing id ⇒ prints `None` | neutral (display only) | Kept |
| `__init__.__getattr__` | `except ImportError` ⇒ re-raise with guidance | Verify path unavailable without `[tsa]` | fail-closed | Kept |

---

## Accepted fail-open paths

Three remain, deliberately. Each is a trade against availability or the zero-dependency
promise, and each is visible in the data rather than silent:

1. **`anchor_hash` never raises.** A TSA outage must not block a production decision. The
   cost is that anchoring can fall behind silently — monitor `AnchorQueue.pending` and
   `Ledger.unsealed_count()`.
2. **Write-time verification is skipped without `[tsa]`.** Recorded as
   `verified_at_write=None`, which is distinct from `True`. Anything consuming anchors for
   compliance should treat `None` as "unverified", not as "fine".
3. **`Ledger.verify()` reports rather than raises.** An audit needs the full list of
   violations, not the first one.

## What this audit cannot cover

Fail-open analysis asks whether a *check* is skipped. It cannot ask whether the thing being
checked was correct to begin with. `Ledger.append()` faithfully hashes whatever it is handed;
if the caller passes the wrong `as_of`, every layer above it will confirm the wrong value with
full cryptographic rigour. See `tests/test_record_fidelity.py`, which pins the one property
the hash chain structurally cannot: that the record contains what was actually recorded.
