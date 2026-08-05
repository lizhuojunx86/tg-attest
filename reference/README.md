# reference/ — the original implementation, kept for provenance

**Do not use this code. Do not copy from it.** It is here so the history of the package is
inspectable, not because it is fit to run.

The packaged library lives in [`../src/tg_attest/`](../src/tg_attest/). Everything in this
directory predates the review that produced v0.1.0, and six defects found in that review are
still present here, unfixed, on purpose — removing them would defeat the point of keeping the
directory.

Every one of them makes verification report success when it should report failure:

| Defect | Effect if you run this code |
|---|---|
| `verify_bundle` computes `ok` from `all(checks.values())` | A garbage timestamp token verifies as **通过**. `all({})` is `True`, so a parse failure that produces no checks at all passes. |
| `si["signature_algorithm"].hash_algo` used unconditionally | DigiCert and Sectigo tokens raise before the signature is ever checked. Combined with the above: **通过**. Two of the three default TSAs were never actually verified. |
| `_chain_ok` never checks the leaf certificate's validity | A timestamp generated before its signing certificate was issued, or after it expired, is accepted. |
| `_HASH.get(algo, hashes.SHA256)` | An unrecognised digest algorithm is silently treated as SHA-256. |
| Signer lookup falls back to `certs[0]` | When `SignerInfo.sid` matches nothing, verification proceeds against a certificate the signer never claimed. Serial numbers are also compared without the issuer. |
| `anchor_hash` stores the returned token unchecked | A token stamping a different digest is accepted and stored. The nonce is derived from the digest and never verified, so it provides no replay protection. |

A demonstration of the first two, run against live TSAs during the review: a real DigiCert
bundle, verified against an unrelated FreeTSA root, returned `ok=True` and exit code 0.

See [`../CHANGELOG.md`](../CHANGELOG.md) for the fixes and
[`../docs/fail-open-audit.md`](../docs/fail-open-audit.md) for the full audit that found them.

## Why keep it at all

Two reasons.

The package was assembled from this code rather than written fresh, and a compliance library
should be able to show where it came from. Diffing `src/tg_attest/record.py` against
`reference/record.py` shows exactly what changed and what didn't — the Merkle construction, the
canonical JSON rules, and the DER request encoder are unchanged.

And it is a concrete example of the thing this library is about. This code worked. It was tested
against three live timestamp authorities and printed a row of green checks. The output was
fluent and the conclusion was wrong. That gap — between a verifier that runs and a verifier that
verifies — is the whole reason the package has an integrity profile, a required-checks list, and
a fail-open audit.

This directory is excluded from linting and is not part of the distributed package.
