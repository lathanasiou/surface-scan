## What does this PR do?

<!-- Brief description. Link any related issue: Closes #123 -->

## Type of change

- [ ] New technology signature
- [ ] New advisory profile
- [ ] Detection improvement (fewer false positives/negatives)
- [ ] Core code / feature
- [ ] Docs
- [ ] Other

## Checklist

- [ ] Tests pass (`python tests/test_e2e.py` and `python tests/test_pipeline.py`)
- [ ] For a new signature: I added a mock profile + assertion in `tests/`
- [ ] For an advisory: `tech` maps to a detectable technology; version ranges only
- [ ] I did **not** add exploitation, WAF-bypass, or intrusive payloads (out of scope)
- [ ] `ruff check .` is clean (or only pre-existing issues)
- [ ] Docs updated if behaviour changed

## Notes for reviewers

<!-- Anything that helps review -->
