# Provenance, corrections and limits

Prepared locally on 2026-11-06 for the authors' second article. The original archived runs were produced in May 2026 according to their metadata. No new simulations were used to verify the paper's numerical claims.

The research code originates from the authors' repository [svpog/yanovskyi-phd-resilience](https://github.com/svpog/yanovskyi-phd-resilience), inspected at commit `9225f94d0615eaea4398cc9ec101c44b6f1fea0d` during the 2026-11-05 audit. Eleven key code/configuration/protocol files matched the local research files byte-for-byte; the comparison is in `audit/reference/github_comparison.json`. This is a historical comparison, not a claim about the repository's current HEAD. The raw S3/S3B/S3C and derived S3A results were absent from that inspected GitHub tree and are included here from the authors' local archive.

`source/` is a selected, unchanged subset of that local research archive. It includes dependencies needed for B1–B4 but not unrelated article-3/4 experiments, reinforcement-learning code, local environments, machine-specific files or the unpublished manuscript. Each distributed source file has its original SHA-256 recorded in `audit/source_manifest.json`. Simulation code, parameters, raw numerical results, original protocol DOCX files, and historical reports were not edited.

New portable scripts live outside `source/`. `recompute_audit.py` is adapted from the 2026-11-05 audit by replacing machine-specific input/output defaults with repository-relative paths and making manifest paths relative. The inferential calculations are unchanged. Supplementary checks explicitly expose the differing time origins, irreversible-set nesting and tied rankings. Reference CSV files copied from the reviewed audit retain their full numerical precision.

Historical outputs may contain superseded interpretations: the original B4 rank procedure separated tied values arbitrarily, and B4 Bonferroni correction was performed within each rule. Corrected tied ranks and the joint family of 108 comparisons are separate audited outputs; original records remain intact.

## Limits and remaining questions

- The tested environment describes this audit/release preparation, not the unavailable complete original simulation lock. Full stochastic reruns may differ across dependency versions; the released raw data are the basis for checking the published numbers.
- Full 27,800-run simulation regeneration was not part of release preparation. The release check reruns the statistical audit from all archived trajectories and performs a small isolated B1 simulation smoke check.
- N=50, h≤8, synthetic hub topologies, single-commodity maximum flow and a random repair policy limit external validity. No empirical supply-chain validation or larger-network scaling study is supplied.
- Discrete damage budgets and non-nested irreversible sets prevent treating the w grid as a smooth nested intervention. A separate design is required for continuous sensitivity claims.
- Identical outcomes in the studied rule comparisons are not statistical evidence of general rule equivalence. Jaccard overlaps quantify only this finite sample.
- Bootstrap intervals cover paired median differences, not all derived aggregate indices. Sensitivity to recovery speed and empirical topology remains open.
- GitHub repository URL, release tag/archive DOI, and final article DOI must be added only once they exist. The published repository and its release provide the public research companion; no archival DOI is claimed.

## Publication

Repository: https://github.com/svpog/article2-targeted-hub-fragility. The manuscript cites release v1.0.0. Article DOI and an archival dataset DOI remain to be added when issued.
