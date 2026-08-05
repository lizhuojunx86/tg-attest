# Releasing tg-attest

Once the one-time setup below is done, releasing is: update the CHANGELOG, tag, push. Everything
else — tests, build, TestPyPI, a real install-and-verify from TestPyPI, PyPI, the GitHub Release —
runs from [`.github/workflows/release.yml`](.github/workflows/release.yml) with no further input.

There are no tokens in this repository and none in GitHub secrets. Publishing uses PyPI
**Trusted Publishing**: GitHub mints a short-lived OIDC token, PyPI checks it came from this
repo, this workflow file, and this environment. Nothing long-lived exists to leak or rotate.

---

## Part 1 — One-time setup

Six steps. All six require a browser session as you; none can be automated, and the reason is
the same in every case: they are identity and trust decisions on accounts that only you control.
A CI job that could configure its own publisher would defeat the point of Trusted Publishing.

### 1. Create the GitHub repository

The repo does not exist yet. `git ls-remote` returns `Repository not found`.

```bash
gh repo create lizhuojunx86/tg-attest --public \
  --description "Tamper-evident decision records for AI systems, anchored to RFC 3161 timestamps."
```

**Why only you:** creating a public repository publishes the code. That is an irreversible
outward-facing act and a public/private choice, both yours.

### 2. Create the two GitHub environments

<https://github.com/lizhuojunx86/tg-attest/settings/environments>

Create two, exactly these names — `release.yml` refers to them by name and a typo fails the job
after the build has already run:

| Name | Protection rules |
|---|---|
| `testpypi` | none |
| `pypi` | none for now — see "Adding a reviewer" below |

Leave both empty. No secrets, no variables. The environments exist so PyPI can scope its trust
to them, not to hold anything.

**Why only you:** repository settings need owner rights on the repo.

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

### 6. Push

```bash
git push -u origin main --follow-tags
```

`v0.1.0` is already tagged locally. Pushing it with `--follow-tags` triggers the release
workflow immediately — so do steps 1–5 first, or the run will fail at the publish step and you
will need to re-tag.

If you would rather push the code first and release separately:

```bash
git push -u origin main          # no tags, no release
# ... verify CI is green ...
git push origin v0.1.0           # this triggers the release
```

**Why only you:** it publishes the repository.

---

## Part 2 — Every release after that

```bash
# 1. Move the Unreleased items into a new version section
$EDITOR CHANGELOG.md

# 2. Commit
git add CHANGELOG.md && git commit -m "docs: changelog for 0.2.0"

# 3. Tag and push
git tag -a v0.2.0 -m "tg-attest 0.2.0"
git push --follow-tags
```

That is all. Watch it at
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

### If something goes wrong

**Failed before the `pypi` job.** Nothing was published to PyPI. Delete the tag, fix, re-tag:

```bash
git tag -d v0.2.0 && git push origin :refs/tags/v0.2.0
```

TestPyPI may already hold that version — TestPyPI is disposable, ignore it and bump to `.dev`
or the next patch when retrying.

**Failed after PyPI published.** The version is permanent; PyPI never allows reuse of a version
number, even after deletion. Yank it and release a new patch:

```bash
# yank via https://pypi.org/manage/project/tg-attest/releases/
git tag -a v0.2.1 -m "tg-attest 0.2.1" && git push --follow-tags
```

**Publishing to TestPyPI only**, to rehearse without touching PyPI: run the workflow manually
from the Actions tab with **skip_pypi** checked.

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
