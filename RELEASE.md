# Releasing tg-attest

Once the one-time setup below is done, releasing is: update the CHANGELOG, tag, push. Everything
else — tests, build, TestPyPI, a real install-and-verify from TestPyPI, PyPI, the GitHub Release —
runs from [`.github/workflows/release.yml`](.github/workflows/release.yml) with no further input.

There are no tokens in this repository and none in GitHub secrets. Publishing uses PyPI
**Trusted Publishing**: GitHub mints a short-lived OIDC token, PyPI checks it came from this
repo, this workflow file, and this environment. Nothing long-lived exists to leak or rotate.

---

## Part 0 — Rehearse before you tag

**Do this first, every time you change anything about releasing.** It is the whole reason the
rest of this document is short.

<https://github.com/lizhuojunx86/tg-attest/actions/workflows/release.yml> → **Run workflow** →
leave **dry_run** checked → Run.

The rehearsal does everything a real release does except touch PyPI:

- verifies Trusted Publishing is configured on **both** indexes, by actually exchanging an OIDC
  token for an upload token (and immediately discarding it)
- runs the full CI matrix, builds, checks the package contents
- publishes a `X.Y.Z.devN` version to TestPyPI, which does not consume a real version number
- installs that from TestPyPI into a clean virtualenv on 3.11 and 3.13 and makes it verify this
  project's own disclosure bundle, plus three negative controls

If it goes green, tagging will work. If it doesn't, you have lost nothing — no tag was used, no
version number was burned, and the job summary tells you which step of Part 1 to go do.

Nothing below needs a tag to test. That is deliberate: the previous release attempt failed
because a tag was pushed before the pipeline existed, and finding that out cost a tag.

## Part 1 — One-time setup

Five steps that only you can do, plus one that usually happens by itself. The reason is the same
in every case: they are identity and trust decisions on accounts that only you control. A CI job
able to configure its own publisher would defeat the point of Trusted Publishing.

### 1. Create the GitHub repository

```bash
gh repo create lizhuojunx86/tg-attest --public \
  --description "Tamper-evident decision records for AI systems, anchored to RFC 3161 timestamps."
```

**Why only you:** creating a public repository publishes the code. That is an irreversible
outward-facing act and a public/private choice, both yours.

*(Already done — the repo exists and is public.)*

### 2. The two GitHub environments — usually nothing to do

`release.yml` references environments named `testpypi` and `pypi`. **GitHub creates them
automatically the first time a job that references them runs**, with no protection rules, which
is exactly what we want. You do not normally need to touch this page.

Verified on this repo: before the first release run, `gh api repos/.../environments` returned
`total_count: 0` — nothing had been auto-created, because no job referencing them had ever run.
They appear on the first rehearsal.

Go to <https://github.com/lizhuojunx86/tg-attest/settings/environments> only if you want to add
protection rules later — see "Adding a reviewer" below.

**Why you'd do it manually:** only to add protection rules, which needs repo owner rights.

### 3. Configure the PyPI trusted publisher

<https://pypi.org/manage/account/publishing/>

The project does not exist on PyPI yet, which is fine — this form creates a **pending
publisher**, and the project is created on first upload. Configuring it before the project
exists is the intended flow, and it also means nobody can claim the name in between.

Fill in exactly:

| Field | Value |
|---|---|
| PyPI Project Name | `tg-attest` |
| Owner | `lizhuojunx86` |
| Repository name | `tg-attest` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

**Why only you:** it authenticates against your PyPI account. This step *is* the trust anchor —
it is the statement "uploads to tg-attest may come from this workflow in this repo." Delegating
it would be handing over the ability to publish under your name.

### 4. Configure the TestPyPI trusted publisher

<https://test.pypi.org/manage/account/publishing/>

Same form, same values, **except**:

| Field | Value |
|---|---|
| Environment name | `testpypi` |

TestPyPI is a separate service with separate accounts. Register at
<https://test.pypi.org/account/register/> if you have not.

**Why only you:** same as step 3.

### 5. Allow the workflow to create releases

<https://github.com/lizhuojunx86/tg-attest/settings/actions>

Under **Workflow permissions**, confirm *Read and write permissions* is available. The workflow
requests `contents: write` only in the `github-release` job, but the repo has to permit it.

**Why only you:** repository settings.

### 6. Push the code, then rehearse, then tag

**Three separate commands. Do not combine them.**

```bash
git push origin main             # code only — no tag, no release
```

Then run the Part 0 rehearsal and wait for it to go green. Only then:

```bash
git push origin v0.1.0           # this, and only this, triggers a release
```

**Never use `--follow-tags` as your normal push.** It pushes commits and tags together, which
means the code and the release start in the same instant — and if the pipeline on the remote is
not yet the pipeline you just wrote locally, you find out by burning a tag. That is exactly what
happened before: `git push -u origin main --follow-tags` sent a tag pointing at a commit that
predated `release.yml`, so no release workflow existed to run.

**Why only you:** it publishes the repository.

---

## Part 2 — Every release after that

```bash
# 1. Move the Unreleased items into a new version section
$EDITOR CHANGELOG.md

# 2. Commit and push the code
git add CHANGELOG.md && git commit -m "docs: changelog for 0.2.0"
git push origin main

# 3. Tag and push the tag — separately
git tag -a v0.2.0 -m "tg-attest 0.2.0"
git push origin v0.2.0
```

Two pushes, deliberately. The first gets the code and any pipeline changes onto the remote; the
second starts the release against a remote that already has them. Combining them with
`--follow-tags` reintroduces the ordering hazard for no benefit — you save one command and give
up the ability to see CI go green before releasing.

Watch it at
<https://github.com/lizhuojunx86/tg-attest/actions/workflows/release.yml>.

The version number comes from the tag via setuptools-scm. Do not edit a version anywhere —
there is no version string in `pyproject.toml` or `__init__.py` to edit, and
`tests/test_version.py` fails if one reappears.

### The CHANGELOG section is required

`release.yml` extracts the section for the version being released and uses it as the GitHub
Release body. If `## [0.2.0]` is missing or under 80 characters, **the release aborts before
anything is published**. A version with no release notes is not worth shipping, and finding out
at the end is worse than finding out at the start.

### What the pipeline does

```
tag pushed
  → ci            full matrix: lint, tests on 3.11/3.12/3.13, zero-dep install, build checks
  → checks        tag format is vX.Y.Z; CHANGELOG has a non-empty section for it
  → build         sdist + wheel; version must equal the tag; reference/ must be absent;
                  sdist must contain the repro bundle and a runnable test suite
  → testpypi      publish with PEP 740 attestations         [environment: testpypi]
  → verify        install tg-attest[tsa]==<version> from TestPyPI into a clean venv on
                  3.11 and 3.13, then run both README repro commands plus three negative
                  controls (tampered bundle rejected, no-trust-root rejected, zero-dep
                  install has no crypto libraries)
  → pypi          publish with PEP 740 attestations         [environment: pypi]
  → release       GitHub Release from the CHANGELOG section, with the artifacts attached
```

The verify step is the gate worth understanding. It installs the package the way a user would,
from an index, and makes it verify this project's own disclosure bundle. If that fails, PyPI is
never touched. A library about tamper-evidence must not ship a release it cannot itself verify.

### When the order goes wrong, and how to recover

The failure mode this pipeline is built around: a tag reaches the remote before the thing that
is supposed to act on it. Diagnose before touching anything.

**Step 1 — find out how far it got.**

```bash
gh run list --workflow=release.yml --limit 5
gh run view <run-id> --log-failed          # if there is a run at all

curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/tg-attest/json
curl -s -o /dev/null -w '%{http_code}\n' https://test.pypi.org/pypi/tg-attest/json
```

`404` from an index means the project has never been published there. If the project exists,
check the specific version:

```bash
pip index versions tg-attest
pip index versions tg-attest --index-url https://test.pypi.org/simple/
```

**Step 2 — match the evidence to a case.**

| Case | Evidence | Version reusable? |
|---|---|---|
| **A** — failed before any upload, or never ran | PyPI 404 for this version, TestPyPI 404 for this version | **Yes** |
| **B** — TestPyPI has it, PyPI does not | TestPyPI lists it, PyPI 404 | **Yes** — `skip-existing: true` on the TestPyPI step means a re-run tolerates the duplicate |
| **C** — PyPI has it | PyPI lists the version | **No.** Already released. Do not attempt to republish |

A special sub-case of A worth naming, because it is what happened here: `gh run list
--workflow=release.yml` returns `HTTP 404: workflow release.yml not found on the default
branch`. That means the tag was pushed to a remote whose default branch had no release
pipeline — nothing ran, nothing was uploaded, and the tag is completely reusable.

**Step 3 — recover.**

*Case A or B* — delete the remote tag and push it again. Re-pushing the same tag re-triggers the
workflow. Do not skip to the next version number; an unpublished version has not been used.

```bash
# make sure the fix is on the remote first
git push origin main

# move the local tag onto the commit that has the pipeline, if it isn't there already
git tag -d v0.1.0
git tag -a v0.1.0 -m "tg-attest 0.1.0"

# delete the remote tag, then push the new one
git push origin :refs/tags/v0.1.0
git push origin v0.1.0
```

Rehearse (Part 0) between the first and last command if the failure was a configuration problem
— that is what the rehearsal is for.

*Case C* — the version is permanent. PyPI never allows reuse of a version number, even after
deletion. Do not delete or re-tag. Verify what was published and move on:

```bash
python -m venv /tmp/check && /tmp/check/bin/pip install "tg-attest[tsa]==0.1.0"
cd examples/verify-me
/tmp/check/bin/python -m tg_attest.cli decision_0000.json --ca freetsa_ca.pem
```

If the published version is actually broken, yank it at
<https://pypi.org/manage/project/tg-attest/releases/> and release a patch. Yanking hides it from
resolvers without breaking anyone who pinned it.

### Deleting a tag is safe; publishing is not

Tags are pointers. Deleting and re-pushing one costs nothing as long as no release came out of
it. The irreversible boundary is a successful PyPI upload — everything before that line can be
redone, and nothing after it can. The pipeline is ordered so that everything cheap and
reversible happens before that line, and the rehearsal lets you cross none of it.

---

## Adding a reviewer to the pypi environment

Not enabled, deliberately — as configured, a tag push releases with no interruption.

If you later want a human gate before PyPI (a good idea once other people can push tags):

<https://github.com/lizhuojunx86/tg-attest/settings/environments> → `pypi` →
**Required reviewers** → add yourself → Save.

After that, a tag push runs everything up to and including the TestPyPI verification, then waits
for you to approve in the Actions UI before the `pypi` job starts. Nothing else changes, and no
workflow edit is needed. You can also set a **wait timer** there instead, if a delay is enough
and an approval click is not.

Note the ordering this gives you: by the time you are asked to approve, the package has already
been built, published to TestPyPI, installed from a real index into a clean environment, and
used to verify a real disclosure bundle. You are approving something that has demonstrated it
works, not a diff.

## Verifying a published release

The uploads carry PEP 740 attestations, so the provenance of any file on PyPI is checkable:

```bash
pip download tg-attest==0.1.0 --no-deps
# provenance is shown per-file at https://pypi.org/project/tg-attest/0.1.0/#files
```

The attestation binds each artifact to the workflow run and commit that produced it. For a
library whose entire premise is that records should be verifiable, its own distribution
artifacts being verifiable is not a nice-to-have.
