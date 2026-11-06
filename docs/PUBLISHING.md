# Publishing the prepared candidate

The candidate has been prepared locally; no GitHub repository has been created by this preparation step.

Suggested destination: a separate repository named `article2-targeted-hub-fragility` in the `svpog` account, keeping the original dissertation repository intact.

Once publication is authorized, from the repository directory use an authenticated GitHub account to create and push the repository:

```bash
gh repo create svpog/article2-targeted-hub-fragility --public --source . --remote origin --push
```

This command publishes the files and should only be run as the publication step. Before using it, check whether that destination already exists; if it does, inspect its contents instead of overwriting it.

After the actual repository URL exists:

1. Add the real URL to `CITATION.cff` (`repository-code` and `url`) and the README. Remove the local-candidate status language. Record the completed validation in the release notes.
2. Create a versioned GitHub release from the reviewed commit. For durable scientific citation, archive that release with a DOI-capable service if available; add an issued DOI only after it is assigned.
3. Add a Data and code availability statement to the journal manuscript, linking to the actual repository and specifying the release tag or archived DOI. The statement should say that B1–B4 code, original protocols, raw run results, Q(t) trajectories and statistical verification are provided. B2 must be described as derived from B1.

Regenerate `audit/release_manifest.json` after any edits, verify the new manifest, and commit those changes before making the cited release. The manifest excludes itself, `.git/`, `generated/`, local caches and environments.

The manuscript remains outside this research-data repository. Do not add a submission manuscript, editorial correspondence or other unrelated local files during publication.
