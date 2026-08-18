# tg-attest

[![Verify shipped bundle](https://github.com/lizhuojunx86/tg-attest/actions/workflows/verify-bundle.yml/badge.svg)](https://github.com/lizhuojunx86/tg-attest/actions/workflows/verify-bundle.yml)
[![CI](https://github.com/lizhuojunx86/tg-attest/actions/workflows/ci.yml/badge.svg)](https://github.com/lizhuojunx86/tg-attest/actions/workflows/ci.yml)

Tamper-evident decision records for AI systems.

The first badge is the one that matters: it runs the same two commands you'll find under [Verify it yourself](#verify-it-yourself-in-about-30-seconds), against the disclosure bundle committed to this repo, on every push. It also checks that a tampered bundle gets rejected — a green check that only ever says "pass" is exactly the failure this library exists to prevent.

Sibling project to [TraceGuard](https://github.com/lizhuojunx86/traceguard), which solves the same point-in-time problem for quant backtest pipelines. Separate repo, separate package, no code dependency between them.

The best argument for this library is that I needed it before I had it. Publishing the measurement behind TraceGuard meant proving a specific claim about 2,163 vendor records while redistributing none of them, because the vendor's terms forbid redistribution. A claim you have to prove about data you are not allowed to show is the problem selective disclosure exists to solve. What I built there was a keyed digest per record, coarse magnitude buckets, and the key withheld for one named auditor who can then check any row against their own copy of the feed. That is this repo's core feature, hand-rolled and worse, with a README standing in for the inclusion proof and the timestamp. The constraint came first and the library came second, which is the order I would want to hear about before trusting either.

Your observability stack logs that the model retrieved document X. It does not record what X said at the time, or that X got revised three weeks later. When a regulator asks you to justify a decision from March, "we retrieved X" proves nothing.

tg-attest records the point-in-time state of every piece of evidence a decision consumed, chains the records so nobody can edit one, and anchors the chain to an RFC 3161 timestamp so nobody can rewrite all of them either. Including you. Especially you.

I wrote the original TraceGuard after measuring a commercial fundamentals feed: across 2,163 earnings records, 41.4% of `epsActual` values differ between first-seen and final, and 15.3% of the 2,163 differ enough to flip a long-entry decision. Both numbers come out of one committed file — `analysis/data/eps_revision_qt_pit_2026h1.csv`, 2,163 rows, sha256 pinned in `manifest.json` together with the decision rule and the threshold sensitivity table. `python analysis/eps_revision.py` recomputes them from that file, no dependencies and no vendor account. What is wrong with the measurement is written up in [method](https://github.com/lizhuojunx86/traceguard/blob/main/docs/eps-revision-methodology.md). Same problem, bigger audience now: EU AI Act Article 12 requires automatic event logging for high-risk systems from 2 December 2027, moved back from 2 August 2026 by the Digital Omnibus (Regulation (EU) 2026/1744, in force 27 July 2026). Sixteen months is roughly how long it takes to find out your logs are not admissible as evidence.

## What an auditor receives

One JSON file, 8 KB. They verify it with a CA certificate they obtain themselves — not one you supply. The timestamp checks out with stock `openssl ts`, no install required; the Merkle proof needs either this library or about forty lines written from the spec in the bundle.

Ten checks, each independent — the content hash, the integrity profile, the Merkle inclusion proof, and seven on the timestamp itself. Exit code 1 on any failure, so you can run it over a sample in CI. There's a real bundle committed to this repo and a command that verifies it two sections down; run that rather than reading about it.

The Merkle proof means one decision can be disclosed without exposing the rest of the epoch. Regulators ask about one loan, one claim, one trade. Handing over your whole ledger to answer that is a bad day.

## Verify it yourself, in about 30 seconds

A real disclosure bundle is committed to this repo, timestamped by FreeTSA. Don't take any of the above on faith — check it.

**Without installing anything.** You need `openssl` and nothing else:

```console
$ git clone https://github.com/lizhuojunx86/tg-attest && cd tg-attest/examples/verify-me
$ openssl ts -verify \
    -digest 6127a62bc10984770572d9c574b8bdc5a5f52d373127ad2fd526992b0abcddd6 \
    -in epoch_000.tsr -token_in -CAfile freetsa_ca.pem
Verification: OK
```

That digest is the `epoch_hash` from `decision_0000.json`, and openssl has just confirmed FreeTSA signed it. No part of that command trusts this library.

**With the library**, for the full chain including the Merkle proof and the integrity profile:

```console
$ pip install tg-attest[tsa]
$ python -m tg_attest.cli decision_0000.json --ca freetsa_ca.pem
决策 seq=0  决策时间 2026-08-04T23:35:17.003+00:00
  执行者 alpha-v2/pead  模型 claude-opus-5
  证据 1 条，闸门 1 道
通过
  ✓ 记录内容哈希自洽
  ✓ 记录满足所声明的完整性档案
  ✓ Merkle 包含证明有效
  ✓ 时间戳/eContentType 为 id-ct-TSTInfo
  ✓ 时间戳/messageImprint 匹配 epoch_hash
  ✓ 时间戳/EKU 仅含 timeStamping
  ✓ 时间戳/EKU 扩展为 critical
  ✓ 时间戳/signedAttrs.message-digest 匹配内容
  ✓ 时间戳/TSA 签名有效
  ✓ 时间戳/证书链至可信根
  TSA 签名时间：2026-08-04T23:35:17+00:00

结论：该记录在 2026-08-04T23:35:17+00:00 之前即以此形态存在。
```

Now break it and watch it fail — change one character in the bundle's `output_hash` and run it again. You'll get `✗ 记录内容哈希自洽` and exit code 1.

`freetsa_ca.pem` ships here so the check runs offline. For real evidence you fetch the root yourself, from [freetsa.org](https://freetsa.org/) or your own trust store — a CA that travels with the evidence proves nothing, which is why the disclosure bundle itself contains no certificates.

## Writing records

```python
from tg_attest import Ledger, EvidenceRef, GateVerdict

led = Ledger()
led.append(
    actor={"type": "agent", "id": "underwriting-v3"},
    model={"provider": "anthropic", "id": "claude-opus-5", "params_hash": "cfg-a1b2"},
    inputs={"application_id": "APP-88214"},
    output={"decision": "refer", "confidence_band": "medium"},
    evidence=[EvidenceRef.of(
        "bureau:score:APP-88214",
        {"score": "712"},
        as_of="2026-05-02T20:00:00+00:00",   # when the value was true at the source
    )],
    gates=[GateVerdict("evidence_gate", "pass", {"lookahead_violations": 0})],
    profile="eu-ai-act",         # refuses to write if evidence or gates are missing
)
seal = led.seal_epoch()          # Merkle root over the batch
anchor(seal)                     # RFC 3161 token from your TSA
```

`as_of` and `observed_at` are separate fields on purpose. The gap between them is the whole point.

That `profile` argument is doing more work than it looks like. A hash chain proves a record wasn't edited; it cannot prove the record was complete when written. If your integration quietly stops passing `evidence`, you get a record that hashes, chains, seals and timestamps perfectly — and contains nothing. Cryptography is no help here, because the content is consistent; it's just absent.

So the profile is declared *inside* the record, hashed with everything else, and checked twice: `append()` raises rather than store a record that misses its own declaration, and verification re-checks it offline. A bundle claiming `eu-ai-act` with an empty evidence list fails, and the failure names the missing field.

What it can't catch is you declaring `minimal` for a system that should be on `eu-ai-act`. That's a legal classification, not something a library can infer. Pin it in code review.

## What it doesn't do

Read this part before you adopt it.

It doesn't make your AI correct. It records what your AI did, and when, and on what basis. Those are different problems and this one solves the second.

It doesn't parse model output into claims. Claim extraction needs an LLM, and an audit tool that depends on an unverifiable component isn't an audit tool. The atomic unit here is the retrieval, not the sentence.

It doesn't replace Langfuse, Arize, or LangSmith. Different job — run both. There is no OTel exporter yet; if you want records in your existing traces today, attach `record_hash` to the span yourself. It's one attribute and it's the only value you need to join the two systems.

The bundled default TSAs are **not** eIDAS qualified. Article 41(1) means a non-qualified timestamp is still admissible. Article 41(2) means only a qualified one shifts the burden of proof to whoever disputes it. Pick a QTSP from the [EU Trusted List](https://eidas.ec.europa.eu/efda/trust-services/) before you rely on this in a dispute, and record the provider's qualified status at stamping time. Qualification gets suspended and withdrawn; checking at verification time is checking too late.

That last point is the same problem the library exists to solve, showing up in the trust anchor itself.

## What we found in our own code

These four documents are the most useful thing in this repository, and they are all about
places where this library was wrong or still is.

| | |
|---|---|
| [**docs/fail-open-audit.md**](docs/fail-open-audit.md) | Every `except`, default branch and `.get(key, default)` in the package, each judged on one question: when this path is taken, does the result get stricter or looser? Six were looser. Three fail-open paths remain, deliberately, and they're named. |
| [**docs/mutation-testing.md**](docs/mutation-testing.md) | Line coverage said 100% while three fail-open defects sat on covered lines. Mutation testing asks the useful question instead — if the code were wrong, would a test fail? It found four chain-validation branches that no test reached, all of which accepted evidence they should have rejected. |
| [**docs/claims-evidence.md**](docs/claims-evidence.md) | Every factual claim in this README, with the test or measurement backing it. Five claims failed the check and were rewritten weaker. One of them — "working against three live TSAs" — had been true only in the sense that it printed a pass. |
| [**docs/threat-model.md**](docs/threat-model.md) | What this defends against and what it doesn't. The second half is longer than the first. |

Also: [docs/article12.md](docs/article12.md) maps EU AI Act Article 12 requirement by
requirement onto what this library does and does not cover, and
[SECURITY.md](SECURITY.md) is the disclosure policy.

## Install

```bash
pip install tg-attest              # writing path, zero dependencies
pip install tg-attest[tsa]         # verification path, adds asn1crypto + cryptography
```

Releases are published from a GitHub Actions workflow via PyPI Trusted Publishing — no API
tokens exist for this project — and every artifact carries a [PEP 740](https://peps.python.org/pep-0740/)
attestation binding it to the commit and workflow run that built it. Check it:

```bash
pip download tg-attest --no-deps
# per-file provenance at https://pypi.org/project/tg-attest/#files
```

A library that asks you to trust its records should be able to show where its own artifacts came
from. See [RELEASE.md](RELEASE.md) for the pipeline, including the step that installs each
release from TestPyPI and makes it verify this project's own disclosure bundle before PyPI is
touched at all.

The write path runs in your production loop, so it requires nothing but the standard library. If `[tsa]` happens to be installed, anchoring also checks on the spot that the token it got back stamps the hash it sent and echoes the nonce — a cheap way to catch a substituted response now rather than at audit time. Without it that check is skipped and recorded as skipped, never as passed.

The verify path runs in an auditor's hands or a nightly job, so it's allowed dependencies. The request encoder is byte-for-byte identical to `openssl ts -query -sha256 -cert`, verified in CI. Signature verification is not hand-rolled.

## License

Apache-2.0. Copyright held by Li Zhuojun.

## Status

v0.1. Working end to end against three live TSAs. API will move before v1.

If you're working through Article 12 and I got something wrong, open an issue. I'd rather be corrected early.

Li Zhuojun
