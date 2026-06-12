# Public Witness Log

This repository publishes timestamped SHA256 digests for private/local research and archive manifests.

The underlying private material is **not** published here. Each witness entry commits to the existence and integrity of a local manifest as of the Git commit date. Later, if needed, the private artifact and manifest can be disclosed or verified against the public digest.

This is not a claim of authorship over every underlying item; it is an integrity and timestamp witness for selected research/archive states.

## Privacy rule

Public witness entries should contain only:

- date
- hash algorithm
- manifest SHA256 digest
- previous public witness SHA256 digest, if any
- generic scope label, if useful

Public witness entries should **not** contain:

- raw research notes
- local filesystem paths
- private filenames
- private archive coordinates
- unpublished model/project details
- credentials, tokens, keys, or private logs

Use generic scope labels by default, such as `selected private/local research/archive manifest`. Add project names only when they are already public and intentionally cleared for this witness.

## Date convention

All date-named witness entries use UTC dates. A witness file named
`witnesses/2026/2026-06-12.md` is the UTC-date witness for `2026-06-12`.

## Verification ladder

A future verifier can check:

1. the disclosed artifact hashes to the private manifest entry;
2. the private manifest hashes to the `manifest_sha256` in a public witness file;
3. the public witness file hashes to the chain entry;
4. the Git commit shows the witness was publicly present by that time.

## Private manifest schema, if later disclosed

Private manifests are not published in this repository. If Fox later discloses a
private manifest for verification, each manifest entry should be interpretable
without access to the original scripts.

Example dummy JSONL row:

```json
{"schema_version":"1","artifact_id":"dummy-redacted-id","artifact_sha256":"<sha256 of raw artifact bytes>","hash_algorithm":"SHA256","size_bytes":12345,"recorded_at_utc":"2026-06-12T14:31:19Z"}
```

Verification rule:

1. Hash the disclosed artifact bytes with SHA256.
2. Confirm the result equals `artifact_sha256` in the disclosed private manifest.
3. Hash the disclosed private manifest file bytes with SHA256.
4. Confirm the result equals `manifest_sha256` in the public witness file.
5. Hash the public witness file bytes with SHA256.
6. Confirm the result equals `witness_sha256` in `chain/daily-chain.jsonl`.

Fields may be redacted or omitted from public discussion when they would reveal
private paths, filenames, archive coordinates, or unpublished project details;
the public witness commits only to the manifest file hash.

## Chain JSONL schema

Each line in `chain/daily-chain.jsonl` is one JSON object:

```json
{"date_utc":"2026-06-12","manifest_sha256":"<sha256>","previous_witness_sha256":null,"scope":"selected private/local research/archive manifest","witness_file":"witnesses/2026/2026-06-12.md","witness_sha256":"<sha256>"}
```

`previous_witness_sha256` links each entry to the prior public witness file hash.

## Repository layout

```text
witnesses/YYYY/YYYY-MM-DD.md   # public daily witness entries
chain/daily-chain.jsonl        # tamper-evident chain index
scripts/make_public_witness.py # creates a witness from a private manifest hash
scripts/verify_chain.py        # checks witness file hashes and previous-hash links
templates/public-witness-template.md
```

## Daily flow

From this repository:
```bash
python3 scripts/make_public_witness.py --manifest /path/to/private/YYYY-MM-DD_manifest.jsonl
python3 scripts/verify_chain.py
# Optional external timestamp proof for the public witness file:
ots stamp witnesses/YYYY/YYYY-MM-DD.md
# Commit the witness file, chain row, and .ots proof when an OpenTimestamps proof was created:
git add witnesses/YYYY/YYYY-MM-DD.md witnesses/YYYY/YYYY-MM-DD.md.ots chain/daily-chain.jsonl
git commit -m "Witness digest YYYY-MM-DD"
git push
```

OpenTimestamps note: a fresh `.ots` proof normally starts as a pending calendar attestation. After Bitcoin confirmation is available, run:

```bash
ots upgrade witnesses/YYYY/YYYY-MM-DD.md.ots
ots verify witnesses/YYYY/YYYY-MM-DD.md.ots -f witnesses/YYYY/YYYY-MM-DD.md
```

Optional, for cleared public project labels:

```bash
python3 scripts/make_public_witness.py \
  --manifest /path/to/private/YYYY-MM-DD_manifest.jsonl \
  --scope "selected public/private boundary manifest"
```
