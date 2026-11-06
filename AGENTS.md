# Research companion maintenance

- Treat `source/` and `audit/reference/` as immutable archived evidence.
- Keep new computations in ignored `generated/`; never overwrite released raw results.
- Use scripts outside `source/` for corrections and explain any methodological changes in `docs/`.
- After numerical changes, run the documented audit and compare regenerated tables.
- When changing distributed files, regenerate `audit/release_manifest.json` and verify it before a new release.
- Never invent a GitHub URL, release DOI, article DOI, or a simulation validation result. Record what was actually run.
