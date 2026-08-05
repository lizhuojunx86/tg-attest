# Threat model

What `tg-attest` defends against, what it doesn't, and where the boundary actually sits.

The value of this document is in the second half. Read that part before you adopt the library,
not after somebody disputes a record.

## The claim

One sentence, and it's deliberately narrow:

> This decision record existed in exactly this form before the time signed by the timestamp authority.

That's it. Not that the decision was correct. Not that the evidence was accurate. Not that the
person named in `actor` is who they say they are. Just: this content, before that time.

Every defence below serves that one claim, and every limitation is a place where the claim
stops.

## Adversaries

| | Capability |
|---|---|
| **A1 — outsider** | Can read a disclosed bundle. Cannot write to your systems. |
| **A2 — insider, application-level** | Can call the API, can write records. Cannot rewrite storage directly. |
| **A3 — insider, storage-level** | Full read/write on the ledger store. This is the interesting one — it includes you. |
| **A4 — network** | Can intercept and modify traffic between you and the TSA. |
| **A5 — colluding TSA** | The timestamp authority itself signs dishonestly, or backdates. |

## What it defends against

### Editing one record (A2, A3)

Each record's `record_hash` covers every field of its own body. Change any field and the hash no
longer matches. Covered by `tests/test_tamper.py::test_A_*` — every field is parametrised, because
"this field doesn't matter" is not a thing that exists in an audit.

### Editing a record and recomputing its hash (A3)

Defeats the per-record check, but each record's `prev_hash` pins the one before it, so the next
record's link breaks. Covered by `test_B_resealed_middle_record_caught_by_forward_chain`.

### Rebuilding the entire chain (A3) — the one that matters

An attacker with storage access can rewrite a record, recompute its hash, and then rebuild every
subsequent record so the chain is self-consistent again. **The hash chain alone does not stop
this**, and we have a test that asserts the failure explicitly rather than hiding it:
`test_B_rebuilding_the_whole_tail_defeats_the_chain`.

What stops it is that the epoch's Merkle root was submitted to a TSA and signed. The attacker
would have to produce a valid TSA signature over the new root, bearing the old time. They can't,
unless they are A5.

This is the whole argument for `anchor.py`. Before anchoring, the ledger detects tampering by
other people. After anchoring, it detects tampering by its owner. Those are different products.

### Modifying the last record (A3)

Nothing points at the last record, so the forward chain is intact, and if the attacker recomputes
the hash the per-record check passes too. Before sealing, this tamper is genuinely invisible —
asserted in `test_C_last_record_resealed_is_invisible_without_a_seal`.

Only the sealed, anchored Merkle root catches it. **The exposure window is everything since the
last seal.** Seal frequently. Epoch roots are chained, so anchoring epoch N bounds the existence
time of every epoch before it — you need to seal often, but you don't need to anchor every seal.

### Deleting or reordering records (A3)

Both change the Merkle root of the sealed epoch. Truncating the tail doesn't break the forward
chain at all, so again the seal is what catches it.

### Forging a disclosure bundle (A1)

Four independent layers, each of which the forger has to defeat: record content → `record_hash` →
Merkle inclusion proof → `epoch_hash` → TSA `messageImprint` → TSA signature → certificate chain.
`tests/test_bundle.py` walks an attacker up this ladder one rung at a time, checking that each
higher layer stops them once they've defeated the one below.

### Substituting the trust anchor (A1)

The bundle contains no CA certificate, and `test_bundle_carries_no_ca_certificate` enforces that.
If the trust root travelled with the evidence, a forger would simply include their own root and
the proof would be circular. The verifier must obtain the CA independently.

`verify_bundle` refuses to return `ok=True` when no `ca_bundle` is supplied — not a warning, a
failure. "No trust root but everything else looked fine" is the single most likely way for this
library to be misused.

## What it does not defend against

### The decision being wrong

Out of scope, permanently. The library records what was decided and on what basis. If the model
was biased, the evidence was garbage, or the prompt was leading, all of that is faithfully and
tamper-evidently recorded. Accurate records of a bad decision.

### Garbage in

`EvidenceRef.of()` hashes whatever you hand it. If your application records an `as_of` that
doesn't match the value's true validity time at the source, the record is precisely wrong forever.
Nothing downstream can detect this — the hash is over what you claimed, not over reality. The
library moves trust from "the log wasn't edited" to "the code that wrote the log was correct."
That is a real improvement and it is not the same as trust elimination.

### Fields the integration forgot to fill in

This is the sharpest edge of the previous point, and it deserves its own entry because it is the
failure this whole product category is most exposed to.

`record_hash` is computed *after* the fields are assigned. So a record that never received its
evidence hashes correctly, links correctly, seals correctly, and gets timestamped correctly.
`Ledger.verify()` returns `[]`. The CLI prints 通过. You end up holding cryptographically
impeccable proof of a record with nothing in it. **No amount of hashing detects this** — hashes
protect the immutability of content, not its presence.

**What the integrity profile does about it.** Each record declares which profile it follows, and
the profile name is part of the hashed body, so the declaration cannot be downgraded after the
fact:

| Profile | Requires |
|---|---|
| `minimal` (default) | `actor.id`, `model.id`, `inputs_hash`, `output_hash` |
| `eu-ai-act` | the above, plus ≥1 evidence, ≥1 gate, and `source_id` / `as_of` / `observed_at` / `value_hash` on every evidence item |

`Ledger.append()` validates on write and raises `ProfileViolation` rather than storing a record
that doesn't meet its own declaration — fail-closed, because a record that fails to write is a
fixable problem and a record that lies is not. `verify_bundle()` re-checks the same rules
offline from the bundle alone, as one of the ten required checks. A bundle claiming `eu-ai-act`
with an empty evidence list fails verification even though every hash in it is perfect.

**What it does not do.** It cannot tell you that you picked the wrong profile. An integration
that should be recording under `eu-ai-act` and declares `minimal` instead produces records that
are fully compliant with what they claim, and empty of the thing that matters. The library has
no way to know whether your system is high-risk under Annex III — that classification is a legal
judgment made outside the code.

So the profile converts *silent field loss* into *a verification failure*. It does not convert
*choosing the weaker standard* into anything at all. If you are deploying this for Article 12
purposes, the decision to use `eu-ai-act` is a control that lives in your code review and your
deployment configuration, not in this library. Pin it there.

### A decision that was never recorded

There is no way to prove a ledger is *complete*. `seq` is contiguous and the chain is unbroken, so
you cannot delete a record from the middle after sealing — but a decision that never called
`append()` leaves no trace of its absence. Completeness is an application-architecture property:
make the audit write non-optional on the decision path, not a callback someone can forget.

### Identity

`actor` is a dict you supply. The library never checks it. `{"type": "human", "id": "alice"}`
means a caller typed that string. Binding it to a real authenticated person is your IdP's job, and
Article 12(2)(d) does ask for it.

### Backdating at write time (A2)

`decided_at` defaults to your local clock, and an application-level attacker can pass any value.
The TSA timestamp bounds records from *above* — it proves they existed no later than genTime. It
says nothing about how much earlier they really were. If lower bounds matter, anchor more often;
the gap between consecutive anchors is exactly your uncertainty window.

### A malicious or compromised TSA (A5)

If the TSA signs a false time, the timestamp is worthless. Mitigations, in order of cost:

- Use a QTSP from the EU Trusted List. Qualification means audits and supervision, not just
  correct ASN.1.
- Anchor the same root to more than one TSA. `AnchorQueue` takes a tuple of providers, and
  falls through them; collusion across independent providers is a much stronger assumption.
- Note that `AnchorQueue.flush()` stops at the first success. That's a cost decision, not a
  security one. If you want multiple independent signatures over the same root, call
  `anchor_hash()` per provider yourself and keep every token.

### Network substitution at anchor time (A4)

Two of the three default TSAs are plain `http://`, so a network attacker sits in a position to
replace the response with a well-formed, genuinely-signed token for a *different* digest.

`anchor_hash()` defends against this when the `[tsa]` extra is installed: before returning, it
reads the token's `messageImprint` and compares it to the digest that was submitted, and checks
that the nonce came back unchanged. A mismatch sets `verified_at_write=False`, which makes
`Anchor.ok` false — the anchor is unusable rather than quietly wrong.

The nonce is `secrets.randbits(64)`. It was previously derived as `sha256(digest + b"nonce")[:8]`,
which anyone holding the digest could compute, and nothing checked the echo — so it provided no
replay protection whatever. RFC 3161 §2.4.1 wants it unpredictable, and it only means anything
if someone verifies it came back.

**The gap that remains:** without `[tsa]`, none of this runs. The field is then
`verified_at_write=None` — "not checked", deliberately distinct from `True`. A stored token
whose flag is `None` has not been shown to stamp anything in particular, and nothing will fail
until an auditor tries to verify it, by which time re-stamping the original root at the original
time is impossible.

Mitigations, in order of effort:

- install `[tsa]` on whatever runs the anchoring — the check is then automatic;
- otherwise re-verify anchors in a nightly job that does have it:
  `verify_token(anchor.token_bytes(), epoch_hash, ca)`;
- prefer `https://` TSA endpoints where the provider offers them;
- treat `verified_at_write is None` as unverified in any compliance reporting, not as fine.

### Revoked certificates

`_chain_ok()` does no CRL or OCSP checking. Offline verification can't fetch them, and the correct
question for a timestamp is whether the certificate was valid *at genTime*, which needs the TSA's
archived revocation data. If a TSA key is compromised and revoked, tokens it signed before the
compromise should still be good, and tokens signed after should not — this library cannot tell
them apart. Long-term archival formats (CAdES-A, RFC 4998 ERS) exist to solve this. Not
implemented.

The signing certificate's own validity period *is* checked against genTime, as RFC 3161 §2.4.1
requires. That check was missing in the reference implementation and is pinned now by
`test_signer_cert_validity_is_checked_against_gentime`.

### Long-term cryptographic decay

Everything here is SHA-256. If SHA-256 falls, every record and every timestamp falls with it.
Records kept for six months are fine. Records kept for a decade need re-anchoring under a stronger
algorithm before the old one weakens — the standard answer is periodic re-timestamping
(RFC 4998 / CAdES-A), which re-stamps the old token with new algorithms while the old signature is
still trustworthy. Not implemented, and there is no migration path in the current schema.

Related, and smaller: `_verify_sig` handles RSA PKCS#1 v1.5 and ECDSA. A TSA signing with RSASSA-PSS
will fail verification. That direction of failure is safe — it rejects rather than accepts — but
it is a compatibility gap, not a feature.

### Availability

`anchor_hash()` never raises; failures come back as an `Anchor` carrying an `error`, and
`AnchorQueue` retains the queue for a later retry. This is deliberate: a TSA outage must never
block a production decision path. The cost is that anchoring can silently fall behind. **Monitor
`AnchorQueue.pending`.** A queue that stops draining means your exposure window is growing, and
nothing in the library will tell you.

### Everything about the storage layer

The reference `Ledger` is a Python list in memory. It has no durability, no concurrency control,
and no access control, and it does not survive a restart. Two processes appending concurrently
will produce a corrupt chain. This is a reference implementation of the record format, not a
database. See [article12.md](article12.md) for what production storage needs to provide.

## Failure direction

One design rule runs through the verification path: **when in doubt, refuse.**

- Empty check set is not a pass — `all([])` is `True`, and zero checks passing is not verification.
- Any error recorded is not a pass, even if every check that ran returned `True`.
- No trust root is not a pass.
- An unknown signature algorithm is not a pass.

This is stricter than the reference implementation was, and it is stricter on purpose. A verifier
that wrongly rejects generates a bug report. A verifier that wrongly accepts generates nothing at
all, until the day it matters.
