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

## Verification ladder

A future verifier can check:

1. the disclosed artifact hashes to the private manifest entry;
2. the private manifest hashes to the `manifest_sha256` in a public witness file;
3. the public witness file hashes to the chain entry;
4. the Git commit shows the witness was publicly present by that time.

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
git add witnesses chain
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
