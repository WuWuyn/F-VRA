# PyShare

PyShare is a Python vulnerability reachability analysis product focused on
mapping CVEs to vulnerable Python functions and checking whether application
usage can reach them.

The project intentionally excludes baseline SCA. Its production scope is:

1. CVE-to-vulnerable-function localization.
2. Vulnerable-function knowledge storage.
3. Package call graphs and `S_i` / `S_o` summaries.
4. Project entry points and external API usage.
5. Compositional vulnerability reachability.

## Modules

| Module | Responsibility | Documentation |
| --- | --- | --- |
| Localization | CVE metadata, patches, AST extraction, candidate retrieval and ranking | [Localization](docs/localization.md) |
| Package analysis | Library call graph, public APIs, `S_i` and `S_o` | [Package analysis](docs/package-analysis.md) |
| Project analysis | Entrypoints, reachable project graph and Usage Index | [Project analysis](docs/project-analysis.md) |
| Reachability | Compose Usage Index and package summaries into paths | [Reachability](docs/reachability.md) |
| Knowledge base | Vulnerable-function records and repository contract | [Knowledge base](docs/knowledge-base.md) |

Other directories such as `reporting`, `storage`, `integrations`, and
`evaluation` are reserved product boundaries. Their module documentation should
be added when they expose runnable behavior.

## Quick Start

```sh
# Run once if conda-lock is not installed in the base Conda installation.
conda install -n base -c conda-forge conda-lock
conda-lock install -n pyshare-vf conda-lock.yml
conda activate pyshare-vf
python -m pip install --no-deps --editable .
pytest
```

Run CVE-to-VF localization:

```sh
pyshare localize CVE-2023-32681 \
  --auto-resolve-patch \
  --top-k 20 \
  --output report.json
```

When `--repository` is omitted or points to a path that does not exist, PyShare
tries to infer a GitHub repository from CVE metadata and clones it into the
repository cache automatically.

LLM and embedding calls use an OpenAI-compatible provider configured through
`LOCAL_LLM_*` and `LOCAL_EMBEDDING_*` environment variables. The local `.env`
can point both chat and embedding traffic at the same `/v1` endpoint.

See the [documentation index](docs/index.md) or the
[localization guide](docs/localization.md)
for environment variables, diagnostics, patch-present and patch-absent modes.

## Recreate RQ3: CVE-to-VF localization

This section covers the **RQ3 localization experiment only**: D_LEX, D_SEM,
P_DUAL with patch present/hidden, and an offline ORACLE control. It does not run
downstream reachability. Use the mode-specific `eval vf-*` commands below; the
older `rq3-run` workflow is a separate runner.

### Frozen experiment inputs

The full frozen input set currently used for the experiment is:

| Item | Value |
| --- | --- |
| Input ID | `vf-input-aa79242b904b7c68` |
| Input directory | `experiments/vf/inputs/vf-input-aa79242b904b7c68/` |
| `manifest.json` SHA-256 | `8a33c0eb29f5555b1195bb22a5d65de665dbce594101a329368556f6b74d7090` |
| Source manifest | `experiments/vf/prepared_manifest_v6.jsonl` |
| D_LEX / D_SEM / ORACLE cases | 1,697 each (1,694 eligible) |
| P_DUAL_PRESENT / P_DUAL_HIDDEN cases | 1,672 each; identical cohorts |
| FunctionCatalogs | 1,617 unique source snapshots |

Keep this input ID and its checksums identical across workers and the
aggregation machine. Do not edit the frozen mode JSONL files or `manifest.json`.
The frozen manifest, mode JSONL files, normalized ground truth, oracle control,
and six shard plans are checked into Git at the paths shown below. They total
about 55 MB plus 0.36 MB for the plans, so a normal clone includes the run
inputs. Docker is not required for this localization workflow. Source snapshots,
the 32.8 GB `catalogs/` directory, and the 12.0 GB `inventory_cache/` directory
are runtime artifacts and are intentionally excluded from Git. Reuse the
matching caches already installed on each worker; a clean machine without them
must first obtain the source snapshots and prepare the catalogs/caches.
Workers also need every source snapshot referenced by the mode inputs. This input uses
`experiments/vf/source_cache/snapshots/`,
`experiments/vf/source_cache/release_snapshots/`, and an external
`~/rq3-snapshots/` cache. If that last cache is stored elsewhere, set
`PYSHARE_RQ3_SNAPSHOT_ROOT` in the machine's `.env`. The aggregator needs the
small `ground_truth.jsonl` and `oracle.jsonl` files; it does not need source
snapshots or catalogs to merge results and calculate metrics.

If the prepared input folder is missing but the source snapshots are available,
prepare it once on a machine with the frozen v6 manifest:

```sh
python -m pyshare.cli.main eval vf-prepare --cases experiments/vf/prepared_manifest_v6.jsonl --output-root experiments/vf/inputs --workers 2
```

This creates 1,617 catalogs and parser caches. Skip it when the matching input
folder and artifacts are already installed; preparation is not required just to
make machine assignments.

### Environment and API configuration

The Conda lock pins Python 3.11 and dependencies for Linux, Windows, and macOS.
On each machine, from the repository root:

```sh
# Run the first command only if conda-lock is not already installed in base.
conda install -n base -c conda-forge conda-lock
conda-lock install -n pyshare-vf conda-lock.yml
conda activate pyshare-vf
python -m pip install --no-deps --editable .
python --version
```

Use the same pushed repository revision on every worker; the merge checks code
and environment fingerprints. The RQ3 runner code, frozen mode inputs, and
shard plans are committed, so clone or pull that revision on each machine and
record it with `git rev-parse HEAD`. Do not copy local uncommitted files. The
Python version should report 3.11.x.

Configure chat and embedding API credentials locally on each worker, in its
own `.env` at the repository root. Do not transfer this file or commit secrets.
Set the same provider/model/endpoint and retrieval settings on every worker.
The aggregation machine also needs those non-secret settings to verify its
fingerprint, but it makes no API calls and does not need API keys.

```dotenv
LOCAL_LLM_API_KEY=...
LOCAL_LLM_BASE_URL=https://provider.example/v1
LOCAL_LLM_MODEL=your-chat-model
LOCAL_EMBEDDING_API_KEY=...
LOCAL_EMBEDDING_BASE_URL=https://provider.example/v1
LOCAL_EMBEDDING_MODEL=your-embedding-model
# Optional if snapshots are not under ~/rq3-snapshots:
# PYSHARE_RQ3_SNAPSHOT_ROOT=/path/to/rq3-snapshots
```

### Create and distribute six shard plans

The six plans generated for this workspace are committed under
`experiments/vf/shard-plans/vf-input-aa79242b904b7c68/`. Each machine can use its
plan directly after cloning; no separate plan transfer is needed. To recreate
the plans on the coordinator (this reads the small inputs only and makes no
model/API calls):

```sh
python -m pyshare.cli.main eval vf-shard-plan experiments/vf/inputs/vf-input-aa79242b904b7c68 --shard-count 6 --output-root experiments/vf/shard-plans/vf-input-aa79242b904b7c68
```

Each machine uses its own `shard_manifest.json`; do not recreate source,
catalog, or parser-cache artifacts that are already present. The prepared
`manifest.json` and four worker mode files are committed under the same input
ID. Frozen Windows paths are resolved against the local repository layout and
`PYSHARE_RQ3_SNAPSHOT_ROOT`.

| Worker | Eligible cases | P_DUAL cases |
| --- | ---: | ---: |
| `machine-001-of-006` | 287 | 286 |
| `machine-002-of-006` | 291 | 289 |
| `machine-003-of-006` | 279 | 274 |
| `machine-004-of-006` | 300 | 296 |
| `machine-005-of-006` | 264 | 260 |
| `machine-006-of-006` | 273 | 267 |

The six generated plans total 363,237 bytes; no source, catalog, or parser-cache
files are copied by this plan-based distribution path.

### Run a shard and resume it

Start with one worker and a one-case canary. The canary exercises the configured
provider for D_SEM and both P_DUAL modes; it uses real API calls. After checking
that records complete and the provider is not throttling, resume with two case
workers. Keep the same run ID. Replace `machine-001-of-006` with the plan for
each worker:

```sh
python -m pyshare.cli.main eval vf-run-index-shard experiments/vf/inputs/vf-input-aa79242b904b7c68 experiments/vf/shard-plans/vf-input-aa79242b904b7c68/machine-001-of-006/shard_manifest.json --run-id vf-v6-main --workers 1 --case-limit 1
python -m pyshare.cli.main eval vf-run-index-shard experiments/vf/inputs/vf-input-aa79242b904b7c68 experiments/vf/shard-plans/vf-input-aa79242b904b7c68/machine-001-of-006/shard_manifest.json --run-id vf-v6-main --workers 2 --case-limit 0
```

Each worker writes one JSONL per mode and durable checkpoints under
`experiments/vf/results/vf-v6-main/machine-XXX-of-006/`. Failed records are
saved and retried on resume. Run the modes in this command as a unit so
P_DUAL_PRESENT runs before P_DUAL_HIDDEN and can reuse the local embedding
cache.

### Merge and report

Copy the six completed `machine-XXX-of-006` result directories to the
aggregation machine. Keep the full prepared input directory there, including
`ground_truth.jsonl` and `oracle.jsonl`. Then merge and calculate metrics
offline; these steps make no model/API calls:

```sh
python -m pyshare.cli.main eval vf-merge experiments/vf/inputs/vf-input-aa79242b904b7c68 --shard-run-dir experiments/vf/results/vf-v6-main/machine-001-of-006 --shard-run-dir experiments/vf/results/vf-v6-main/machine-002-of-006 --shard-run-dir experiments/vf/results/vf-v6-main/machine-003-of-006 --shard-run-dir experiments/vf/results/vf-v6-main/machine-004-of-006 --shard-run-dir experiments/vf/results/vf-v6-main/machine-005-of-006 --shard-run-dir experiments/vf/results/vf-v6-main/machine-006-of-006 --run-id vf-v6-main --output-root experiments/vf/results
python -m pyshare.cli.main eval vf-metrics experiments/vf/inputs/vf-input-aa79242b904b7c68 experiments/vf/results/vf-v6-main
```

The report is written under `experiments/vf/results/vf-v6-main/report/` as
JSON, CSV, and Markdown. It reports root-cause-only and all-valid-anchor
metrics, Hit@1/3/5/10, MRR, P_DUAL CandidateRecall@100, D_SEM extraction
coverage/failures, runtime and token usage, plus paired PRESENT-minus-HIDDEN
deltas. ORACLE is generated centrally from normalized ground truth. More
detail is in the [VF experiment guide](experiments/vf/MODE_PIPELINE.md).

`pyshare scan` is already present as a CLI boundary, but the current scan
service still returns `UNKNOWN` until the project analyzer, KB, and persisted
package-summary loader are wired together. This product path is separate from
the RQ3 CVE-to-VF localization experiment above.

## Repository Layout

```text
pyshare/
|-- README.md
|-- configs/
|-- src/
|-- data/
|   |-- raw/
|   |-- interim/
|   `-- benchmarks/
|-- artifacts/
|-- experiments/
|   |-- audits/
|   |-- current_cve_vf/
|   |-- dataset/
|   |-- dependency_build/
|   |-- oracle/
|   |-- protocol/
|   `-- vf/                  # RQ3 inputs, run IDs, caches, and reports
|-- outputs/                  # Human review workbooks and exports
|-- results/
|   |-- tables/
|   |-- figures/
|   |-- metrics/
|   `-- logs/
|-- tools/
`-- docs/
```

Canonical benchmark inputs live in `data/benchmarks/`. RQ3/VF experiment
manifests and run directories live directly in `experiments/vf/`; run IDs keep
individual runs distinct without a versioned parent directory.

## Source Layout

```text
src/pyshare/
|-- analysis/
|   |-- callgraph/
|   |-- dependencies/
|   |-- package/
|   `-- project/
|-- cli/
|-- core/
|   `-- kb/
|-- cve_vf/
|-- localization/
|   |-- code/
|   |-- providers/
|   |-- ranking/
|   |-- retrieval/
|   `-- sources/
|-- reachability/
|-- reporting/
|-- storage/
|-- integrations/
`-- evaluation/
```

`pyshare` is the single import root. Analysis, localization, reachability,
storage, and CVE/VF helpers live under that package instead of separate
top-level namespaces. API services, workers, web UI, Docker application shells,
and server database adapters are intentionally left out.

For a source-tree import check without installation:

```sh
PYTHONPATH=src python -c "import pyshare; from pyshare.cli.main import app"
```

For the reproducible, distributed CVE-to-VF experiment, use the locked Conda environment and follow [the VF mode pipeline guide](experiments/vf/MODE_PIPELINE.md) to prepare inputs once, create machine shards, run each shard, merge the outputs, and calculate metrics offline.

For a focused reachability regression:

```sh
pytest tests/unit/test_reachability.py
```

## Jarvis Local Project Scan

Local project scans are controlled by `configs/local_projects.json`. Keep real
project checkouts under `data/raw/projects/` and list them in that manifest;
experiment scripts should not clone arbitrary repositories.

The current manifest contains only:

```text
alerta -> https://github.com/alerta/alerta.git
```

Prepare the local checkout:

```sh
git clone --depth 1 https://github.com/alerta/alerta.git data/raw/projects/alerta
git -C data/raw/projects/alerta rev-parse HEAD
```

Jarvis is expected at `tool/Jarvis/jarvis_cli.py` under
`PYSHARE_JARVIS_ROOT`. For the vendored pythonJaRvis engine:

```sh
export PYSHARE_JARVIS_ROOT="vendor/pythonJaRvis/Jarvis"
```

The repository vendors the engine at upstream commit
`8871b86494a1aec0095686ffa543994a7361af88`. The local runner uses the
separate Conda environment `.tools/jarvis-py38` (Python 3.8.20, `networkx`
3.1, and `setuptools<81`); this avoids running the upstream import hook under
the host Python version. The adapter prefers this interpreter automatically.

The two package-scoped graph policies are independent in upstream JARVIS:

```text
EA-like: package modules, no --entry_point
AA-like: package modules, --entry_point <qualified function names>
EW-like: package modules, --decy
AW-like: package modules, --decy --entry_point <qualified function names>
```

For a local smoke run, use `--runner local`; the Docker runner is the
paper-faithful option for dependency traversal and requires Docker Desktop to
be running.

Run Jarvis through Docker's Python 3.8 image:

```sh
python experiments/run_jarvis_local_project.py \
  --project-id alerta \
  --runner docker \
  --timeout 300
```

Expected result on the pinned Alerta commit:

```text
PASS jarvis alerta
report: results\metrics\jarvis_alerta_project_graph.json
nodes: 403
edges: 994
usage_index: 36
```

If Docker Desktop is installed but stopped, start it first and confirm:

```sh
docker info --format '{{.ServerVersion}}'
```

## Legacy SCA Import

Legacy metadata and scanner tooling from
`FPT-University-Lab/feagle@old-sca-tools` is preserved under:

- `tools/`: original SCA runner scripts and helper Dockerfile.
- `data/raw/sca/legacy_inventory/`: imported raw SCA outputs, checkpoints, and summaries.
- `data/raw/metadata/cloned-projects-metadata.json`: imported project inventory.
- `src/pyshare/cve_vf/legacy/`: old advisory/annotation import helpers that still
  depend on the former server database package.
