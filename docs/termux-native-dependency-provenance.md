# Termux native dependency provenance

This investigation is isolated on `compat/termux-native-dependency-provenance`.
It does not change application dependency pins, PR #41, or `main`.

## Exact compatibility target

- Android / Termux, CPython 3.14, aarch64.
- OpenAI SDK selection and adoption are out of scope. The production baseline remains `openai==1.40.0`; newer SDK evaluation is isolated in PR #41.
- `jiter==0.18.0`.
- `pydantic-core==2.50.4`.

No version substitution is permitted. In particular, the community fork's
older `jiter 0.13.0` and `pydantic-core 2.46.4` recipes and the archived
Eutalix `pydantic-core 2.50.0` wheel are excluded from source resolution,
build inputs, artifacts, and installation.

## jiter 0.18.0 source identity

Canonical upstream source:

- Repository: `https://github.com/pydantic/jiter`
- Release source commit: `fc2da0bd1fb699a6c4e9641e9e1c06fa6d5d93e8`
- Source distribution: `jiter-0.18.0.tar.gz`
- Source URL: `https://files.pythonhosted.org/packages/source/j/jiter/jiter-0.18.0.tar.gz`
- SHA-256: `a0ca63fd9450a212e4e658d4cfe0ab4977c4f9b0003c68828b843c65e27662ff`
- Upstream `Cargo.toml` blob SHA: `ed65c92bab81b5ef6ae15086824e1d954b7b810f`
- Upstream `Cargo.lock` blob SHA: `05c56d738864db4b1fd393cfb8a288326189e969`
- Cargo workspace version: `0.18.0`; PyO3: `0.30.1`; Rust MSRV: `1.88`.
- Upstream Python build backend requirement: `maturin>=1.15.0,<2`.

PyPI's Trusted Publishing provenance for the source archive identifies the
upstream repository, commit, and publishing workflow. The Termux build recipe
still independently checks the archive's SHA-256 before compilation.

## pydantic-core 2.50.4 source identity

Canonical upstream source:

- Repository: `https://github.com/pydantic/pydantic`
- Release tag: `core-v2.50.4` (Pydantic's documented tag convention for
  pydantic-core releases since v2.13).
- Source directory: `pydantic-core/`
- `Cargo.toml` blob SHA at that tag:
  `45caa9b792ebdd6e716b8941f13551bc0023a10d`.
- `Cargo.lock` blob SHA at that tag:
  `c8372d38030d6ad8bc6776dc00a745d0d400c9a0`.
- `pyproject.toml` blob SHA at that tag:
  `db7fd428c958cd449f3f2f741cf77ece0d842153`.

The tagged `Cargo.toml` declares package version `2.50.4` and
`jiter = 0.18.0`; its lockfile also resolves `jiter 0.18.0`. Its build
backend requires `maturin>=1.16.0,<2`. The CI source-identity job checks out
this exact tag, records its resolved commit SHA, and asserts all three facts.

PyPI lists the `pydantic_core 2.50.4` sdist and wheels without publishing
provenance. Therefore, a PyPI archive is not treated as authenticated source.
The official Git tag is the source identity for this investigation. The
2.50.4 source may not be replaced with 2.50.0, 2.46.4, or another release.

## Controlled jiter build inputs

Two clean, independent GitHub-hosted runners build the same package recipe.
Both use:

- Official Termux package build repository at commit
  `74a426129b7e868858a7b2329b9a12a5da0c5250`.
- Official Termux package-builder container pinned by digest:
  `ghcr.io/termux/package-builder@sha256:44999857244619e25bc8e3427904a16d36cc0c0e087704af039e5bdf94814ac9`.
- Termux package builder's pinned Rust recipe: `1.99.1`.
- Termux package builder's pinned maturin recipe: `1.16.0`.
- Termux Android NDK major version: `30`.
- The exact jiter 0.18.0 source URL and SHA-256 above.
- The Termux package recipe in `packaging/termux/python-jiter/build.sh`.

The recipe uses Termux's cross-Python environment, Cargo's locked dependency
resolution through `MATURIN_PEP517_ARGS=--locked`, and the official Termux
Android cross-build environment. The initial two-run build exposed a duplicate
`libpython3.14.so` entry because the cross-link had already emitted the
dependency before the recipe's post-install patch. That first artifact is
superseded and is not approved. The recipe now adds the dependency only when
absent and fails unless exactly one `libpython3.14.so` NEEDED entry remains.
The verification job also checks the Termux RUNPATH and rejects GLIBC symbol
version requirements.

## Acceptance gates

The reproducibility workflow must:

1. Verify the official source identities and declared versions.
2. Verify the jiter source archive against its pinned SHA-256.
3. Build twice on separate clean runners with the pinned official builder.
4. Inspect the output extension's ELF machine, dynamic dependencies, Python
   linkage, and absence of GLIBC-versioned symbol requirements.
5. Compare both the native extension SHA-256 values and the complete Termux
   package SHA-256 values. Any mismatch fails the reproducibility gate.
6. Generate a GitHub/Sigstore build attestation only after the two builds match.

No artifact is approved for installation until the full gate passes and the
actual Termux device smoke test succeeds. This CI build is a cross-build and
cannot replace the device test.
