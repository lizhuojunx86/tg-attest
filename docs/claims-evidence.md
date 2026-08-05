# Claim-by-claim evidence table

Every factual assertion in `README.md`, `docs/article12.md` and `docs/threat-model.md`, with
what backs it. This project sells verifiability; a claim in the README that does not survive
checking damages the whole argument more than a missing feature would.

Status values: **Holds** (test or measurement backs it) · **Holds, qualified** (true within a
stated limit) · **Corrected** (was wrong, README changed) · **Unverifiable here** (true or not,
this repo cannot show it).

---

## README.md

| # | Claim | Evidence | Status |
|---|---|---|---|
| 1 | "no code dependency between them" (TraceGuard) | `test_no_traceguard_dependency` greps every shipped module for `import traceguard` | **Holds** |
| 2 | "records the point-in-time state of every piece of evidence" | `EvidenceRef` carries `as_of` + `observed_at` + `value_hash`; `test_append_preserves_evidence_and_gates`, `test_A_evidence_tampering_is_caught` | **Holds** |
| 3 | "chains the records so nobody can edit one" | `test_A_*` (11 field-level cases), `test_B_resealed_middle_record_caught_by_forward_chain` | **Holds** |
| 4 | "anchors the chain to an RFC 3161 timestamp so nobody can rewrite all of them either" | `test_C_last_record_resealed_is_caught_by_the_sealed_merkle_root`; the counter-case is asserted explicitly in `test_B_rebuilding_the_whole_tail_defeats_the_chain` | **Holds** |
| 5 | "across 2,163 earnings records, 41.4% of `epsActual` values differ between first-seen and final, and 15.3% of the 2,163 differ enough to flip a trading decision" | Measurement from the TraceGuard project on a commercial feed, and published there rather than only asserted: 896/2163 differ, 332/2163 flip, both recomputable from committed data with `python analysis/eps_revision.py`, with the decision rule and a twelve-item limitations section in [the method doc](https://github.com/lizhuojunx86/traceguard/blob/main/docs/eps-revision-methodology.md). No code in *this* repo reproduces it. | **Corrected** → the earlier wording, "15.3% **of those**", made the 896 differing records the denominator instead of the 2,163. That describes a different and smaller quantity: 15.3% of 896 is 137 records, where 332 actually flip. The true conditional rate is 332/896 = 37.1%. Both headline rates are over the same 2,163. Now verifiable in the sibling repo, though still not here |
| 6 | "EU AI Act Article 12 has required full reconstructability of algorithmic decisions since August 2, 2026" | Date is right — Chapter III obligations apply 2026-08-02. "Full reconstructability" is not what Article 12 says: it requires automatic recording of events (logs) enabling traceability. | **Corrected** → "has required automatic event logging … since" |
| 7 | "One JSON file, 8 KB" | `fixtures/decision_0000.json` is 8382 bytes | **Holds** |
| 8 | "They verify it with a CA certificate they obtain themselves" | `test_bundle_carries_no_ca_certificate`; `verify_bundle(b, None)` refuses to pass | **Holds** |
| 9 | "They don't need this library, your database, or your cooperation" | The *timestamp* verifies with stock `openssl ts` (`test_token_written_to_disk_is_a_valid_tsr`). The *Merkle proof* does not — it needs this library or a reimplementation from the documented spec. | **Corrected** → now says the timestamp needs only openssl, and the proof needs either this library or ~40 lines from the spec |
| 10 | Sample CLI output block | Showed 6 check lines; the CLI prints 9. Timestamp format also differed (`Z` vs `+00:00`, no milliseconds). | **Corrected** → replaced with actual verbatim output |
| 11 | "Nine checks, each independent" | `len(BUNDLE_REQUIRED_CHECKS) == 9`; `test_every_link_in_the_chain_is_actually_checked` names all nine | **Holds** |
| 12 | "Exit code 1 on any failure" | `test_cli_exit_one_without_ca`, `test_cli_exit_one_on_tampered`, `test_cli_exit_zero_on_valid` | **Holds** |
| 13 | "one decision can be disclosed without exposing the rest of the epoch" | `test_bundle_does_not_contain_other_records`; `test_disclose_from_an_earlier_epoch_uses_the_right_span_and_index` | **Holds** |
| 14 | "`as_of` and `observed_at` are separate fields on purpose" | Both are distinct fields on `EvidenceRef`; `test_append_preserves_evidence_and_gates` pins both | **Holds** |
| 15 | "It doesn't make your AI correct" | Statement of scope, and an accurate one | **Holds** |
| 16 | "It doesn't parse model output into claims" | No LLM, no heuristics anywhere in `src/` | **Holds** |
| 17 | "Records emit as OTel span attributes, so run both" | **No OTel code exists.** The only mention is an unimplemented item in `record.py`'s TODO list. | **Corrected** → now states OTel export is not implemented and names what to do instead |
| 18 | "The bundled default TSAs are **not** eIDAS qualified" | FreeTSA, DigiCert, Sectigo are absent from the EU Trusted List; `DEFAULT_TSAS` carries the warning | **Holds** |
| 19 | "Article 41(1) means a non-qualified timestamp is still admissible" | eIDAS Art. 41(1): a timestamp shall not be denied legal effect solely for being electronic or non-qualified | **Holds** |
| 20 | "Article 41(2) means only a qualified one shifts the burden of proof" | eIDAS Art. 41(2): qualified timestamps enjoy a presumption of accuracy of time and integrity of data | **Holds** |
| 21 | "pip install tg-attest — writing path, zero dependencies" | `dependencies = []`; CI `zero-deps` job installs without extras in a clean env and runs the whole write path; `test_write_path_has_no_module_level_third_party_import` | **Holds** |
| 22 | "The write path … uses nothing but the standard library" | True for *required* dependencies. Since the write-time token check was added, `anchor.py` will use `asn1crypto` **if it is already installed**, via a function-local import guarded by `except ImportError`. | **Corrected** → added "requires nothing but", and a sentence describing the optional check |
| 23 | "The request encoder is byte-for-byte identical to `openssl ts -query -sha256 -cert`, verified in CI" | `test_matches_openssl_ts_query` over 5 payloads; the CI job additionally fails if that test was skipped | **Holds** |
| 24 | "Signature verification is not hand-rolled" | `verify.py` uses `asn1crypto` + `cryptography` throughout; the only hand-written DER is the *request* encoder, which is byte-compared against openssl | **Holds** |
| 25 | "Working end to end against three live TSAs" | `test_network.py`, 9 tests against FreeTSA / DigiCert / Sectigo, all passing. **This was false at the last review** — two of the three never had their signatures verified (see `docs/mutation-testing.md`). It is true now. | **Holds** |
| 26 | "Apache-2.0. Copyright held by Li Zhuojun." | `LICENSE`; `pyproject.toml` `license = "Apache-2.0"`, `authors` | **Holds** |

## docs/article12.md

| Claim | Evidence | Status |
|---|---|---|
| Article 12 applies to high-risk systems from 2026-08-02 | AI Act Chapter III application date | **Holds** |
| Article 19 sets a 6-month minimum log retention | AI Act Art. 19 | **Holds** |
| Article 26(6) — deployers keep logs ≥ 6 months | AI Act Art. 26(6) | **Holds** |
| Longer retention for some Annex III categories | Deliberately hedged — the doc says "check the regime that applies to you rather than assuming a single number" rather than naming a figure | **Holds, qualified** |
| The library does **not** cover retention, access control, identity attribution | Accurate: no storage backend, no authz, `actor` is an unvalidated dict | **Holds** |
| "12(2)(d) — not covered" | `actor.id` is never checked against anything | **Holds** |
| Reconstructability caveat for non-deterministic models | Statement of scope | **Holds** |

## docs/threat-model.md

| Claim | Evidence | Status |
|---|---|---|
| Editing one record is caught | `test_A_*` | **Holds** |
| Editing + rehashing is caught by the forward chain | `test_B_resealed_middle_record_caught_by_forward_chain` | **Holds** |
| Rebuilding the whole chain defeats hashing alone | `test_B_rebuilding_the_whole_tail_defeats_the_chain` asserts the failure | **Holds** |
| Only the anchored Merkle root catches a tampered last record | `test_C_*` (both directions) | **Holds** |
| Bundle carries no CA certificate | `test_bundle_carries_no_ca_certificate`, `test_export_bundle_roundtrip_keeps_token_out_of_the_epoch` | **Holds** |
| "The write path does not verify the token it receives" | **No longer true.** Fixed this round: `_verify_at_write` checks messageImprint + nonce echo when `[tsa]` is present. | **Corrected** → section rewritten to describe the remaining gap (no `[tsa]` ⇒ no check) |
| Nonce provides no replay protection | **No longer true.** `secrets.randbits(64)` + echo verification. | **Corrected** |
| No CRL/OCSP checking | Accurate; `_chain_ok` does no revocation checking | **Holds** |
| Signing certificate validity checked at genTime | `test_regression_leaf_cert_validity_checked_at_gentime`, `test_issuer_expired_at_gentime_is_rejected` | **Holds** |
| RSASSA-PSS not supported | `_verify_sig` handles PKCS#1 v1.5 and ECDSA only; fails closed | **Holds** |
| Everything is SHA-256; long archives need re-anchoring | Accurate; no re-timestamping implemented | **Holds** |
| In-memory `Ledger` has no durability or concurrency control | Accurate | **Holds** |

---

## Corrections applied to README.md

Five, all in the direction of claiming less:

1. **OTel** — "Records emit as OTel span attributes" removed. There is no such code. Replaced
   with a statement that the export is not implemented and that `record_hash` is the value to
   attach if you want it in your own traces.
2. **"full reconstructability"** — replaced with "automatic event logging", which is what
   Article 12 actually requires. The stronger word was doing work the regulation does not.
3. **Auditor independence** — split into what openssl alone can do (the timestamp) and what it
   cannot (the Merkle proof).
4. **Sample CLI output** — replaced with verbatim current output, all nine checks.
5. **Zero dependencies** — "uses nothing but" → "requires nothing but", plus one sentence on
   the optional write-time check.

## Standing rule

A claim goes in the README only if something in this repo can be pointed at to support it, or
it is attributed to a source outside the repo. Anything else gets written weaker or left out.
Re-check this table whenever the README changes.
