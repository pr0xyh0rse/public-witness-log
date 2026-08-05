# Public witness template

This template is prospective. Historical witnesses retain their original format.

```text
# Witness — YYYY-MM-DD UTC

hash_algorithm: SHA256
witness_format: public-witness/v2
manifest_schema: public-witness-active-work-watchdog/v3
eligibility_profile: public-witness-cleared-work-roots/v2
generator_sha256: <SHA256 of the exact generator bytes used>
scope: selected private/local active-work witness manifest
manifest_sha256: <SHA256 of the private/local manifest bytes>
previous_witness_sha256: <SHA256 of prior public witness, or null>
private_manifest: not published
raw_material: not published

Statement:
This public witness commits to the existence and integrity of a private/local manifest as of this repository history. The underlying material is intentionally not included here.

Boundary:
This witness is an integrity/timestamp marker, not a public release of the underlying material and not a claim of authorship over every underlying item.
```

The scope and prose are fixed. Do not add project descriptions, root names or counts, private filenames, daily change summaries, or richer activity labels.
