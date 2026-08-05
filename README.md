# Public Witness Log

This repository publishes deliberately sparse, hash-linked witnesses for private/local manifests. A witness supports later integrity and timestamp checks without publishing the manifest or the material it indexes.

## Privacy boundary

Public witnesses contain only:

- a UTC date;
- fixed method identifiers;
- SHA-256 commitments;
- a fixed generic scope;
- fixed nondisclosure and boundary statements; and
- a detached OpenTimestamps proof.

Public documentation and witness entries must **not** contain project descriptions, root names or counts, private filenames, daily change summaries, or richer “what we worked on” labels. The generator and verifier enforce a fixed public scope and fixed witness body. The private manifest and local eligibility policy remain outside this repository.

A hash commitment proves byte equality only when compared with a candidate preimage. It does not disclose, summarize, or independently establish authorship of the underlying material.

## Repository layout

- `witnesses/YYYY/YYYY-MM-DD.md` — sparse public witness
- `witnesses/YYYY/YYYY-MM-DD.md.ots` — detached OpenTimestamps proof
- `chain/daily-chain.jsonl` — append-only hash-chain index
- `scripts/make_public_witness.py` — fail-closed witness generator
- `scripts/verify_chain.py` — chain and witness-format verifier
- `scripts/manage_ots.py` — proof inspection, read-only maturity checks, and isolated upgrades
- `templates/public-witness-template.md` — prospective public format
- `tests/` — policy and regression tests

## Prospective witness format

New witnesses use `public-witness/v2`. They record the manifest schema, eligibility profile, and SHA-256 of the exact generator bytes used. These are method receipts, not descriptions of the committed material.

Historical witnesses remain byte-for-byte unchanged and continue to verify as legacy entries. They are not rewritten merely to adopt a newer format.

## Create a witness

Generation requires two local-only inputs: an eligible private manifest and its matching local source policy.

```bash
python3 scripts/make_public_witness.py \
  --manifest <private-manifest> \
  --source-policy <local-source-policy> \
  --date YYYY-MM-DD
```

The generator fails closed when the schema, eligibility receipt, source-policy digest, or public-repository boundary does not match. `scope` is fixed and cannot be replaced with a descriptive label.

After inspecting the generated witness and chain row, stamp the witness:

```bash
ots stamp witnesses/YYYY/YYYY-MM-DD.md
```

Fresh calendar proofs are normally pending. Stamping is the first stage, not the end of the OpenTimestamps lifecycle.

## Verify the public chain

```bash
python3 scripts/verify_chain.py
```

The verifier checks, among other invariants:

- valid and strictly increasing UTC dates;
- canonical paths confined beneath `witnesses/`;
- exact chain-to-witness hashes and fields;
- SHA-256 syntax and chain linkage;
- fixed scope and fixed public prose;
- complete prospective method provenance; and
- rejection of extra descriptive fields.

Scan tracked public text for absolute local paths and descriptive metadata labels:

```bash
python3 scripts/privacy_scan.py
```

A release gate may additionally supply a local-only newline-delimited token file outside the repository. Token values are never printed:

```bash
python3 scripts/privacy_scan.py --forbidden-token-file <local-private-token-file>
```

## OpenTimestamps lifecycle

### 1. Inspect local proof state

```bash
python3 scripts/manage_ots.py status
```

This is offline. It confirms that every proof commits to its adjacent witness and classifies local proofs as pending or Bitcoin-attested. `ots info` alone does **not** validate a Bitcoin block.

### 2. Check calendars without modifying proofs

```bash
python3 scripts/manage_ots.py check
```

This uses `ots upgrade -n`. It queries allowed calendars but does not change repository files. It is suitable for a periodic read-only maturity check.

### 3. Upgrade mature proofs safely

Choose a backup directory outside the repository:

```bash
python3 scripts/manage_ots.py upgrade \
  --backup-dir <external-backup-directory>
```

The tool upgrades isolated temporary copies, verifies each upgraded proof still commits to the correct witness, requires a Bitcoin block-header attestation, preserves the original proof outside the repository, and only then atomically replaces the public proof. It never commits or pushes changes.

### 4. Verify Bitcoin attestations

The strongest CLI route uses a locally controlled Bitcoin node:

```bash
ots verify witnesses/YYYY/YYYY-MM-DD.md.ots
```

Where a local node is unavailable, the official verifier at [opentimestamps.org](https://opentimestamps.org/) or the official JavaScript client can verify against public block explorers. Explorer verification is convenient but weaker than querying a locally controlled node.

## Read-only CI

The repository CI runs the unit tests, verifies the full witness chain, and checks every detached proof’s commitment and local attestation structure. CI has read-only repository permissions and does not stamp, upgrade, commit, or publish anything.

## Independent verification

An independent verifier can:

1. clone the repository;
2. run `python3 scripts/verify_chain.py`;
3. run `python3 scripts/manage_ots.py status`;
4. verify selected Bitcoin-attested proofs with a local Bitcoin node or the official explorer-backed verifier; and
5. if later given a candidate private manifest by its custodian, hash its exact bytes and compare the result with the corresponding public commitment.

Disclosure of any candidate preimage is a separate decision. Nothing in this repository grants access to private source material.
