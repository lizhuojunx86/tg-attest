# Security policy

## Reporting a vulnerability

Report privately first. Do not open a public issue for a security defect.

**Preferred:** [GitHub private vulnerability reporting](https://github.com/lizhuojunx86/tg-attest/security/advisories/new)
— Security tab → Report a vulnerability. It gives us a private thread and a CVE request path.

**Alternative:** open a GitHub issue titled `security contact request` with no technical detail,
and I will reply with a private channel.

Please include, as far as you have it:

- the version or commit
- what an attacker gets out of it
- a reproduction — a bundle, a token, a script
- whether you intend to disclose publicly, and when

If you already have a disclosure deadline in mind, say so up front. I would rather work to your
schedule than negotiate it after the fact.

## Response commitments

| Stage | Target |
|---|---|
| Acknowledge receipt | 3 working days |
| Initial assessment (severity, affected versions) | 10 working days |
| Fix or documented mitigation, high severity | 30 days from acknowledgement |
| Fix or documented mitigation, other severities | 90 days from acknowledgement |
| Public advisory | With the fix release, or at your deadline, whichever comes first |

This is a single-maintainer project. If a deadline is going to slip you will hear that from me
before it slips, not after. If I go silent for two weeks, treat that as a failure of this policy
and disclose on your own schedule — a library about accountability does not get to hide behind
an unanswered email.

## What counts as a vulnerability here

The severe class is narrow and specific: **anything that makes verification report success when
it should report failure.** That includes

- a forged or altered bundle that `verify_bundle` accepts
- a timestamp token that verifies against a trust root that did not issue it
- a tampered record that `Ledger.verify()` fails to flag once its epoch is sealed and anchored
- a Merkle inclusion proof that validates for a record not in the tree
- any input that makes a required check silently not run — see `docs/fail-open-audit.md`

Also in scope:

- canonical JSON producing different bytes for the same object across platforms or processes
- the DER request encoder diverging from `openssl ts -query -sha256 -cert`
- a third-party dependency appearing in the write path (`record.py`, `anchor.py`) as a hard import
- a hash input containing its own output (self-reference), which invalidates an anchor on write-back

## What is out of scope

These are known and documented, not defects:

- **The three default TSAs are not eIDAS qualified.** Deliberate; see README and
  `docs/article12.md`. Use a QTSP if you need the Article 41(2) presumption.
- **No revocation checking.** `_chain_ok` does no CRL or OCSP lookups. Offline verification
  cannot fetch them; doing it properly needs archived revocation data. See
  `docs/threat-model.md`.
- **No RSASSA-PSS support.** Fails closed. A compatibility gap, not a hole.
- **Write-time token verification is skipped without `[tsa]`.** Recorded as
  `verified_at_write=None`, never as `True`.
- **`anchor_hash()` never raises.** A TSA outage must not block a production decision path.
- **The in-memory `Ledger` has no durability, concurrency control, or access control.** It is a
  reference implementation of the record format. Production needs append-only storage.
- **Garbage in.** If the caller records the wrong `as_of`, everything above it will confirm the
  wrong value correctly. The library moves trust from "the log wasn't edited" to "the code that
  wrote the log was right"; that is an improvement, not trust elimination.
- **`Ledger.verify_disclosure()` returning `True`** does not mean a bundle is admissible — it
  checks structure only, never the timestamp. Documented in its docstring. Use `verify_bundle`.

Reports that a bundle fails to verify when it should pass are welcome as ordinary bugs — but
note the direction. A verifier that wrongly rejects generates a bug report; one that wrongly
accepts generates nothing at all, until the day it matters.

## Supported versions

Pre-1.0. Only the latest release gets fixes. `0.x` versions may change the API; security fixes
will not be backported to earlier `0.x` releases.

## Verifying a release

The write path has no dependencies, so the supply-chain surface is the package itself. Check
what you installed:

```bash
pip download tg-attest --no-deps --no-binary :all:
python -m pytest        # the test suite ships in the sdist
```

If you are relying on this library for compliance evidence, pin an exact version and hash in
your lockfile, and run `python -m tg_attest.cli` against a known-good bundle as a smoke test
after any upgrade. `fixtures/decision_0000.json` is suitable and does not expire — its
verification is anchored to the genTime frozen inside the token, not to the wall clock.
