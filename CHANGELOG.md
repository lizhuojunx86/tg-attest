# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is [semantic](https://semver.org/), with the pre-1.0 caveat that `0.x` minor bumps
may break the API.

## [Unreleased]

### Added

- **eIDAS 合格状态，在盖戳当时记录（issue #2）。** `anchor_hash()` / `AnchorQueue`
  接受一份 EU 可信列表快照，判定这家 TSA 在 `genTime` 那一刻是否为合格时间戳服务，
  结果写进 `Anchor.tsa_qualified` / `eutl_ref` / `qualified_checked_at` /
  `qualified_reason`。三个字段此前只有定义，从未被填过。

  为什么是盖戳当时：合格资质会被暂停、撤销，TSP 每轮换一次密钥就是列表里一条
  状态时间线独立的新条目。同一个问题在不同时刻问会得到不同答案，而只有盖戳那一刻
  的答案是对的。这是本库自己的 point-in-time 命题出现在它的信任根上。

  - `tg_attest.eutl` —— 查询，**零依赖**，跑在写入路径上，已纳入
    `test_zero_deps.py` 的静态检查范围。判定不发网络请求。
  - `tg_attest.eutl_build` —— 快照构建，需要新的 `[eutl]` 额外依赖
    （`lxml`，只用来做排除式 c14n）。`python -m tg_attest.eutl_build -o snap.json`。
  - 判定实现 ETSI TS 119 615 V1.3.1 第 4.6/4.7 节，逐条对应条款，见
    [`docs/eutl.md`](docs/eutl.md)。
  - 信任根是 OJ C/2026/1944 公布的 6 个证书摘要，钉在代码里。选择钉摘要而不是
    钉证书，是为了让信任根小到能用眼睛和官方公报核对。
  - `export_bundle(..., anchor=a)` 把声明写进披露包；`verify_bundle` 如实转述但
    **不**纳入必需检查清单；`cli --eutl` 用审计方自己的快照独立复算并报告不一致。

  三值语义与 `verified_at_write` 一致：`None` 是"没查"，不是"不合格"。把一次网络
  故障固化成法律结论是这个功能最危险的失败方式——爱尔兰在实测构建中确实取不到。

### Fixed

- **enveloped-signature 变换吃掉了 Signature 后面的文本节点。** 该变换省略的是
  Signature 元素及其子树，不包括紧跟其后的文本；`lxml` 的 `remove()` 连 `tail`
  一起删。签名者把换行放在 `Signature.tail` 上的列表（荷兰）因此摘要对不上、
  验签失败，而放在前一个兄弟节点 `tail` 上的（德国、奥地利）删不删都一样。
  同一份代码在一部分成员国上静默失败，症状看起来像对方列表有问题。
  回归测试 `test_the_enveloped_transform_must_not_eat_the_tail` 覆盖三种 tail 形态，
  已验证把修复退回原状时该测试失败。

### Changed

- `cli --json` 的输出多了一个 `attestations` 键。它与 `checks` 分开，**不**参与
  `ok` 的计算：合格状态不受时间戳保护，性质与其余检查不同；而且「是否合格」是
  法律分类，不该成为技术验证的通过条件——用非合格 TSA 的包在技术上完全有效，
  只是举证责任在出具方那边。严格按键集合解析 `--json` 的调用方需要跟一下。

### Known gaps

诚实记下，不当作已解决：

- 合格状态**不受时间戳保护**。它不参与 `epoch_hash`——合格状态要拿到 token 才算得
  出来，而 `epoch_hash` 是被盖戳的输入，回写会让时间戳当场失效（与 `tsa_token`
  同一条约束）。因此这是记录方的一项声明，可被事后修改而不留痕。纳入哈希的方案
  （写进下一个 epoch 的被哈希体）见 issue #3，留给 v0.3。
- 可信列表没有官方历史归档，审计方用今天的快照复算，与包内声明不一致时无法区分
  "资质变了"与"声明不实"。
- TS 119 615 PRO-4.7.4-06 的双重判定本实现只做一次；证书无 `C=` 时降级为全表扫描。
  两处都是对规范的有意偏离，写在 `docs/eutl.md` 里而不是藏在实现里。

### Documentation corrections

- `docs/claims-evidence.md` claimed nine required bundle checks. There are ten — the
  integrity-profile check took the count from nine to ten when it was added, the README was
  updated and this table was not. `len(BUNDLE_REQUIRED_CHECKS) == 10`. The table carries its own
  standing rule to re-check whenever the README changes, and that rule was not followed, so the
  row records the miss rather than quietly reading correctly.

## [0.1.0] — 2026-08-05

First packaged release. The reference implementation had been working end to end against three
live TSAs; turning it into a package surfaced six defects in the verification path, all of which
made verification report success when it should have reported failure. They are listed under
Fixed because a library about accountability should say what was wrong with it, including in
code that never shipped.

### Added

- `tg_attest` package, src-layout. Public API: `Ledger`, `EvidenceRef`, `GateVerdict`,
  `DecisionRecord`, `EpochSeal`, `anchor_hash`, `AnchorQueue`, `verify_token`, `verify_bundle`,
  `export_bundle`.
- **Integrity profiles.** A record declares which profile it follows; the profile name is part
  of the hashed body and so cannot be downgraded afterwards. `minimal` requires `actor.id`,
  `model.id`, `inputs_hash`, `output_hash`. `eu-ai-act` additionally requires at least one
  evidence item and one gate, with `source_id` / `as_of` / `observed_at` / `value_hash` present
  on every evidence item. `Ledger.append()` raises `ProfileViolation` rather than store a record
  that misses its own declaration; `verify_bundle()` re-checks the same rules offline as one of
  the ten required checks.

  This closes the one gap no amount of hashing can: `record_hash` is computed after the fields
  are assigned, so a record whose evidence was never populated hashes, chains, seals and
  timestamps perfectly while containing nothing. It does **not** detect choosing `minimal` where
  `eu-ai-act` was warranted — that is a legal classification, documented as out of scope in
  `docs/threat-model.md`.
- `examples/verify-me/` — a real disclosure bundle, its CA, and the raw `.tsr`, so anyone can
  verify the claims in the README in about thirty seconds, with or without installing anything.
  A dedicated CI workflow runs both routes plus their negative controls on every push.
- `python -m tg_attest.cli` — standalone bundle verifier. Exit code 0 on a full pass, 1
  otherwise. `--json` for machine consumption, now including a `missing` field.
- Zero required dependencies for the write path (`record.py`, `anchor.py`). Verification path
  under the `[tsa]` extra. Enforced by a CI job that installs without extras in a clean
  environment, and by static tests that reject any module-level third-party import.
- `TOKEN_REQUIRED_CHECKS` / `BUNDLE_REQUIRED_CHECKS` — a static list of checks that must all be
  present and true. Replaces a verdict computed from whatever checks happened to run.
- Write-time anchor verification: with `[tsa]` installed, `anchor_hash()` confirms the returned
  token stamps the submitted digest and echoes the nonce. Result recorded on
  `Anchor.verified_at_write` as `True` / `False` / `None` (not checked).
- `Ledger.unsealed_count()` — records not yet covered by any epoch, i.e. the current exposure
  window. Monitor it.
- `Ledger.verify()` now checks epoch coverage: contiguity, inverted ranges, and epochs
  referencing records that do not exist.
- Documentation: `docs/article12.md`, `docs/threat-model.md`, `docs/fail-open-audit.md`,
  `docs/mutation-testing.md`, `docs/claims-evidence.md`, `SECURITY.md`.
- 837 offline tests plus 9 network tests (deselected by default, run nightly in CI).
- Offline fixtures that do not expire, because certificate validity is checked against the
  genTime frozen inside the token rather than the wall clock.
- **Automated release pipeline.** Pushing a `vX.Y.Z` tag runs the full CI matrix, builds, and
  publishes — no tokens anywhere, using PyPI Trusted Publishing (OIDC) with separate `testpypi`
  and `pypi` environments. Every artifact carries a PEP 740 attestation binding it to the commit
  and workflow run that produced it.

  Between TestPyPI and PyPI there is a gate that does the thing this library is about: it
  installs the just-published version from a real index into a clean virtualenv on 3.11 and
  3.13, runs both README reproduction commands against the shipped disclosure bundle, and checks
  three negative controls — a tampered bundle must be rejected, a missing trust root must not
  pass, and the zero-dependency install must contain no crypto libraries. PyPI is not touched
  unless all of that succeeds. Shipping a release that cannot verify its own evidence would be
  the most embarrassing possible failure for this package.
- **Single source of version truth.** The version comes from the git tag via setuptools-scm;
  `__version__` reads package metadata. There is no version string in `pyproject.toml` or
  `__init__.py` to keep in sync, and `tests/test_version.py` fails if one reappears, if a tag
  has no CHANGELOG section, or if a non-tagged build reports a clean release number.
  Two things make the ordering of setup steps stop mattering. A **preflight** stage runs before
  anything else and exchanges a real OIDC token for an upload token on both indexes — discarding
  it immediately — so a missing Trusted Publishing configuration fails in about twenty seconds
  with a pointer to the exact setup step, rather than after ten minutes at the last job with a
  tag already spent. And a **dry run** (manual trigger, on by default) walks the entire path
  except PyPI, publishing a `X.Y.Z.devN` version to TestPyPI, so the whole release can be
  rehearsed without a tag.

  `skip-existing` is set on the TestPyPI upload only. TestPyPI is a draft index and re-running a
  pipeline should not fail because the last attempt already uploaded. It is deliberately absent
  on the PyPI upload, where an existing version must fail loudly — a silent no-op there would
  read as a successful release.
- `RELEASE.md` — the setup that only the maintainer can perform, each step with its URL, the
  exact field values, and why it cannot be automated; the routine for every release after that;
  and a diagnosis-and-recovery section covering what to check, how to tell whether a version is
  still reusable, and the exact commands to re-push a tag.

### Fixed

Six defects in the verification path. Every one of them failed in the direction of accepting
evidence that should have been rejected.

- **`verify_bundle` reported success for a garbage timestamp.** The verdict was
  `all(checks.values())`; when token parsing raised, no timestamp checks were produced and
  `all()` over the two surviving record-level checks returned `True`. `all({})` is also `True`.
  Demonstrated with a real DigiCert bundle verified against an unrelated FreeTSA root: the CLI
  printed 通过 and exited 0. Replaced with the static required-checks list; a missing entry is
  now a failure, and any recorded error forces failure.
- **Two of the three default TSAs never had their signatures verified.** DigiCert and Sectigo
  sign with `rsassa_pkcs1v15`, whose OID does not bind a hash, so
  `si["signature_algorithm"].hash_algo` raised `ValueError` before the signature check ran.
  Combined with the defect above, the result was 通过. Now falls back to
  `SignerInfo.digestAlgorithm` per RFC 5652 §5.3.
- **Signing-certificate validity was not checked at genTime.** `_chain_ok` validated each
  issuer's window but never the leaf's, so a timestamp generated before its certificate was
  issued, or after it expired, was accepted. RFC 3161 §2.4.1 requires it.
- **Unknown digest algorithms defaulted to SHA-256.** `_HASH.get(algo, hashes.SHA256)` turned
  "I don't recognise this" into "assume SHA-256". Now rejects.
- **Signer lookup fell back to the first certificate.** When `SignerInfo.sid` matched nothing,
  verification proceeded against `certs[0]` — a certificate the signer never claimed. The
  lookup also compared serial numbers alone, which are unique only per issuer. Now compares
  issuer and serial, and returns no signer rather than a guess.
- **`verify_inclusion` treated any non-`"L"` side value as "right".** The `"R"` literal was
  never actually compared. Unknown side values are now rejected.

Also fixed, outside the verification path:

- `anchor_hash()` stored whatever token came back without checking it, and derived the nonce
  deterministically from the digest (`sha256(digest + b"nonce")[:8]`) while never verifying the
  echo — so the nonce provided no replay protection at all. Now `secrets.randbits(64)` with
  echo verification.
- `_read_tlv` used `buf[i:i+n]` with no bounds check, silently returning short data for
  truncated DER. Now raises, and rejects indefinite-length encoding.
- `parse_tsr` treated everything after `PKIStatusInfo` as the token, including trailing
  garbage. The token must now be exactly one well-formed SEQUENCE.
- `export_bundle` silently wrote bundles with no timestamp — permanently unverifiable, with no
  warning at export time. Now raises unless `allow_unanchored=True`.
- `export_bundle` used `json.dump(..., default=str)`, which would silently stringify an
  unserialisable value and produce a bundle whose content no longer matched its hash. The
  symptom would have been a hash mismatch months later. Removed.
- `Ledger.verify()` did not check epoch coverage, so a gap between epochs left records covered
  by no Merkle root and therefore anchored by nothing.
- `Ledger.verify_disclosure()` raised on malformed input instead of returning `False`, so
  `if verify_disclosure(b):` crashed rather than taking the else branch.

### Changed

- `Ledger.verify_disclosure()` documents that it checks structure only and never the timestamp.
  Its `True` does not mean a bundle is admissible.
- `verify_token` with no `ca_bundle` no longer writes a placeholder string into `checks`. The
  chain check is reported in `missing`, because it did not run.
- `AnchorQueue.flush()` logs through `logging` instead of printing.
- Removed `anchor.verify_token()` — same name as `verify.verify_token()`, strictly weaker
  (`signature_verified: False`), and it imported `asn1crypto` inside the zero-dependency write
  path.
- Removed `anchor.selftest_against_openssl()`; the byte-for-byte comparison now lives in
  `tests/test_tsq.py`, which also keeps `subprocess` out of the shipped package.

### Documentation corrections

Five claims in the README were corrected in the direction of claiming less. See
`docs/claims-evidence.md` for the full table.

- "Records emit as OTel span attributes" — no such code exists; the export is not implemented.
- "full reconstructability" — Article 12 requires automatic event logging, not that.
- "They don't need this library" — true for the timestamp via openssl, not for the Merkle proof.
- The sample CLI output showed six of nine checks and a timestamp format the tool does not emit.
- "uses nothing but the standard library" — requires nothing but; will use `asn1crypto` for the
  write-time check if it is already installed.

[Unreleased]: https://github.com/lizhuojunx86/tg-attest/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lizhuojunx86/tg-attest/releases/tag/v0.1.0
