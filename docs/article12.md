# EU AI Act Article 12 — what this library covers and what it doesn't

Article 12 (record-keeping) has applied to high-risk systems since 2026-08-02. This document maps
its requirements onto what `tg-attest` actually does. The point of the document is the second column.
A compliance library that claims to cover everything is a liability, because the gaps are still
there — you just find them during the audit instead of during procurement.

Nothing here is legal advice. Article 12 doesn't stand alone either: it is written to serve
Articles 13, 14, 19, 26 and 72, and a control that satisfies 12 can still fail those.

## Scope note

Article 12 applies to **high-risk** AI systems as classified in Article 6 and Annex III.
If your system isn't high-risk, Article 12 doesn't apply to you and this library is at most
an internal integrity control. Check the classification first. Most of the cost of compliance
is in the classification being wrong, not in the logging.

## Requirement by requirement

| Article 12 requirement | Covered? | How, or what's missing |
|---|---|---|
| **12(1)** Technical capability for automatic recording of events over the system's lifetime | **Partial** | `Ledger.append()` records one event per decision. The library provides the record format and the integrity chain; **you** have to call it at every decision point. Nothing here detects a path that forgot to log. |
| **12(2)(a)** Recording of the period of each use | **Partial** | `decided_at` gives a per-decision timestamp. Session start/end and "period of use" are not modelled. Put them in `labels` or record them as their own events. |
| **12(2)(b)** Reference database against which input data was checked | **Yes** | This is what `EvidenceRef` exists for. `source_id` identifies the reference source, `value_hash` pins what it said, `as_of` pins the point in time the value was true at the source, `observed_at` pins when you first saw it. Use the `eu-ai-act` profile and the library refuses to write a record that omits any of them. |
| **12(2)(c)** Input data for which the search led to a match | **Yes** | `inputs_hash` plus the `EvidenceRef` list. Note this is hashes, not content — see "What we deliberately don't store" below. |
| **12(2)(d)** Identification of natural persons involved in verifying results | **No** | `actor` is a free-form dict with `{"type": "human", "id": ...}`. The library never verifies that the id corresponds to a real, authenticated person. Identity attribution needs your IdP. See "External scaffolding" below. |
| **12(3)** Logging appropriate to the intended purpose (Annex III systems) | **Partial** | The record schema is generic. Whether the fields you populate are *appropriate* to your purpose is a judgment the library cannot make and does not attempt to. |
| **Art. 19** Automatically generated logs kept for an appropriate period, minimum 6 months | **No** | The reference `Ledger` keeps records in a Python list. It is memory-only and does not survive a restart. Retention is entirely yours. See below. |
| **Art. 26(6)** Deployer keeps logs at least 6 months | **No** | Same as above. This is a storage and policy question, not a format question. |
| **Art. 72** Post-market monitoring drawing on the logs | **Partial** | `evidence_index()` groups every evidence reference by `source_id`, which is the primitive you need to find all past decisions whose basis has since been revised. The monitoring logic itself is not implemented. |

## What the library does that Article 12 does not explicitly require

These are the parts that matter in a dispute, and they go beyond the text:

**Tamper evidence.** Article 12 says record. It does not say "make the records hard to change."
A log you can silently rewrite answers the letter of the requirement and none of its purpose.
The hash chain plus Merkle sealing means a single altered record is detectable.

**External anchoring.** A hash chain you control is not evidence against you — you have write
access, so you can rebuild the whole thing and it will still be self-consistent. Submitting the
epoch root to an RFC 3161 TSA is what converts "we have logs" into "these records existed in this
form before time T, and you don't have to take our word for it." See [threat-model.md](threat-model.md),
scenario C.

**Selective disclosure.** A regulator asks about one loan, one claim, one trade. The Merkle
inclusion proof lets you produce exactly that record with a proof of its membership in a sealed,
timestamped batch, without handing over the rest of the batch. Article 12 doesn't require this.
Your legal team will want it anyway.

**Point-in-time evidence state.** `as_of` and `observed_at` are separate fields. 12(2)(b) asks
which database you checked against; it doesn't ask what that database *said at the time*. But
"we checked the bureau" proves nothing in March if the bureau revised the record in May. This
is the gap the library was built for, and it is wider than the regulation is currently written.

**Enforcement of your own logging standard.** Article 12 tells you to log; it has nothing to say
about what happens when your integration silently stops populating a field. That failure is
invisible to every cryptographic control in this library — a record missing its evidence hashes,
chains, seals and timestamps exactly as well as a complete one.

Declare the `eu-ai-act` profile and the library refuses the write instead:

```python
led.append(..., profile="eu-ai-act")   # raises ProfileViolation if evidence is empty
```

The profile name is part of the hashed record, so it cannot be downgraded afterwards, and
verification re-checks it offline. What this cannot do is notice that you chose `minimal` for a
system that should have been on `eu-ai-act` — that classification is a legal judgment, and the
library has no basis for making it. Treat the profile argument as a compliance control in your
own code, and review it as one.

## What we deliberately don't store

**Content, by default.** Records hold hashes. `value_ref` and `output_ref` are optional pointers
to your own object storage. Compliance requires traceability, not that the audit layer becomes a
second copy of your data — and a second copy is a second breach surface, a second GDPR erasure
obligation, and a second thing to keep for six months.

The consequence is symmetric and you should be clear-eyed about it: **a hash proves that a value
did not change; it does not reveal what the value was.** If you cannot produce the original value,
you can prove integrity and nothing else. Decide per source whether you keep the value, and put
it somewhere the hash can point at.

**Anything requiring a model to interpret.** No claim extraction, no output parsing, no
"relevance" scoring. The atomic unit is the retrieval, not the sentence. An audit tool whose
conclusions depend on an unverifiable component is not an audit tool — a regulator can ask how
the extraction was validated, and "the LLM decided" is not an answer that survives the question.

## External scaffolding you still need

The library covers the record format and its integrity. These four are yours, and none of them
are small:

**1. Retention and storage.** Article 19 sets a floor of 6 months; national law and sectoral
rules go longer, and Annex III biometric and law-enforcement systems commonly require longer
retention under their own regimes — check the regime that applies to you rather than assuming a
single number. The reference `Ledger` is an in-memory list. Production needs append-only storage:
S3 Object Lock in COMPLIANCE mode, a WORM volume, or a table where the application role holds
INSERT and nothing else. If your database user can `UPDATE`, your hash chain documents tampering
rather than preventing it — which is the intended design, but only works if someone is checking.

**2. Access control and audit of the audit layer.** Who can call `append()`? Who can read
disclosed records? Reading a decision record can be as sensitive as reading the underlying case
file. The library has no access control whatsoever.

**3. Identity attribution.** `actor.id` is a string this library never validates. Article 12(2)(d)
wants natural persons identified. Bind that field to your identity provider and be able to
demonstrate the binding, or the field is decoration.

**4. A qualified timestamp authority.** The three TSAs in `DEFAULT_TSAS` — FreeTSA, DigiCert,
Sectigo — are technically conformant RFC 3161 services and **none of them is an eIDAS qualified
trust service provider**. The distinction is legal, not technical, and it decides who carries the
burden of proof:

- **eIDAS Article 41(1):** a non-qualified timestamp is not denied legal effect merely for being
  electronic. It is admissible. You can still make your case with it.
- **eIDAS Article 41(2):** only a *qualified* timestamp enjoys the presumption of accuracy of the
  time it indicates and of the integrity of the data. With a qualified timestamp, the party
  disputing it has to rebut the presumption. Without one, you are proving your own timestamp.

Pick a QTSP from the [EU Trusted List](https://eidas.ec.europa.eu/efda/trust-services/) before you
rely on this in a dispute.

And record the provider's qualified status **at the time of stamping** — `Anchor` has
`tsa_qualified`, `eutl_ref` and `qualified_checked_at` fields for exactly this, and the library
does not populate them for you. Qualification gets suspended and withdrawn. Checking at
verification time tells you the status today, which is not the question; the question is whether
the timestamp was qualified when it was issued. That is the same point-in-time problem this
library exists to solve, reappearing one level down in the trust anchor. It is worth noticing how
hard this class of problem is to escape.

## Reconstructability

The practical test Article 12 is written toward: given a decision, can you reconstruct why it was
made? What `tg-attest` gives you is:

- the exact inputs (by hash), model, model version and parameter hash
- every piece of evidence consumed, with the value's hash and its `as_of`
- every gate verdict recorded at decision time
- proof that all of the above existed in this form before a third-party-signed timestamp

What it does not give you is the model's reasoning, or a guarantee that re-running the model on
the same inputs produces the same output. Those are different problems. For non-deterministic
models, "reconstructable" means you can establish what was decided and on what basis — not that
you can re-derive the decision. If your regulator reads reconstructability as bit-exact replay,
you need determinism guarantees from your inference stack, and this library will not supply them.
