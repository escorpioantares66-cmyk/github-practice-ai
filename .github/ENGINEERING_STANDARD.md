# AI Engineer Mode - Clean Repo Standard

## Main is always green
- `main` must be Success 20s, 0 warnings
- `ruff check` => All checks passed! (strict, 100 char)
- `pytest` => 6 passed, no-cov
- No `data/`, `.test_rag*`, `__pycache__` committed

## Workflows
- All `.github/workflows/*.yml` use:
    - actions/checkout@v5
    - actions/setup-python@v6
    - ubuntu-latest (notice ok)
- No Node 20 deprecation warnings

## Branching
- Feature branch: `phase-X-description` or `rag-real-phaseX`
- Work: commit small, ruff clean each commit
- Push: `git push --set-upstream origin <branch>`
- PR: Title + Description (no AI tag spam)
- Merge: Squash or no-ff to main, Success required
- Delete: `git branch -d <branch>` + `git push origin --delete <branch>` after merge

## Code Quality (Phase 2 proven)
- Termux aarch64 traps: no numpy wheel, no Rust (nh3/maturin/ruff), use `pkg install ruff`
- `pure-py fallback` + `FAISS_AVAILABLE` flag
- Embedding: mock 384d L2 norm 1.0 tiled to 1536 when sk-test-mocked, real text-embedding-3-small 1536 when real key
- Persistence: JSON + faiss.index in persist_path, survives Termux restarts
- Tests: RealVectorStore, _chunk_text, _mock_embed_384, filter_meta, hybrid, persistence, embedding_dim in [384,1536]

## Before push check (mandatory)
ruff check --fix . && ruff check . && PYTHONPATH=. CI=true OPENAI_API_KEY=sk-test-mocked pytest -v --no-cov

## Commit style
- fix: ruff X
- feat: Phase X wiring
- chore: bump deps, clear warnings
- docs: standard
