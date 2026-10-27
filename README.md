# Preflight

Preflight is an infrastructure change risk analysis engine that parses Terraform plan JSON to detect destructive operations, security regressions, and architectural risks before deployment.

```bash
terraform plan -out=tfplan
terraform show -json tfplan | preflight analyze -
```

---

## Performance & Quality Metrics

Measured across synthetic benchmarks and automated test suites:

| Metric | Measured Value | Standard |
|---|---|---|
| **Analysis Latency** | **< 0.50 ms** avg per plan | Sub-millisecond static evaluation |
| **Detection Rate** | **100%** (11/11 target scenarios) | Synthetic test fixtures |
| **False Positive Rate** | **0** on control fixtures | Clean control plans produce 0 findings |
| **Test Coverage** | **89%** statement coverage | 61 unit and integration tests |
| **Type Safety** | **100%** strictly typed | `mypy --strict` with zero warnings |
| **Code Quality** | **Zero errors** | Compliant with `ruff` linter and formatter |
| **Scoring Determinism** | **100% bit-for-bit identical** | Zero drift across 50 sequential runs |

---

## Installation

Requires Python 3.12+.

```bash
git clone https://github.com/preflight-engine/preflight.git
cd preflight
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

*Package name:* The executable is `preflight`. The distribution package on PyPI is `preflight-engine` to avoid collision with an existing legacy package.

---

## Usage

```bash
# Pipe directly via stdin (recommended for CI/CD)
terraform show -json tfplan | preflight analyze -
terraform show -json tfplan | preflight analyze - --fail-on high

# Analyze a local plan file
preflight analyze plan.json
preflight analyze plan.json --fail-on high
preflight analyze plan.json --environment staging
preflight analyze plan.json --format markdown --output report.md
preflight analyze plan.json --format json --output report.json
```

### Options

| Option | Flag | Description | Default |
|---|---|---|---|
| `--environment` | `-e` | `development`, `staging`, or `production` | `production` |
| `--format` | `-f` | `terminal`, `json`, or `markdown` | `terminal` |
| `--fail-on` | | Block if findings reach: `low`, `moderate`, `high`, `critical` | *None* |
| `--output` | `-o` | Output file path | stdout |
| `--config` | `-c` | Custom YAML configuration path | `preflight.yaml` |
| `--verbose` | `-v` | Show traceback on error | `false` |
| `--version` | `-V` | Display version | |

### Exit Codes

| Code | Status | Meaning |
|:---:|---|---|
| `0` | **Pass** | Analysis completed; no blocking policy conditions triggered. |
| `1` | **Block** | Analysis completed; a configured policy threshold was met. |
| `2` | **Error** | File not found, invalid JSON syntax, or bad configuration. |

---

## Risk Scoring Model

Preflight scores risks from `0.0` to `100.0` using five weighted dimensions:

| Factor | Weight | Evaluation Scope |
|---|:---:|---|
| **Change Impact** | 30% | Structural blast radius (in-place modification vs. resource recreation vs. deletion) |
| **Security Exposure** | 25% | External reachability, administrative port ingress, permissive IAM wildcards |
| **Reversibility** | 20% | Recovery complexity (permanent data loss vs. declarative attribute update) |
| **Environment Criticality** | 15% | Target tier: `development` (1.0/5), `staging` (3.0/5), `production` (5.0/5) |
| **Uncertainty** | 10% | Attributes computed at apply-time that cannot be evaluated statically |

$$\text{Score} = \sum_{i} \left( \text{Weight}_i \times \frac{\text{Factor Score}_i}{5.0} \right)$$

### Risk Categories
- `0 – 24.9`: **Low** (tag updates, read-only data sources, benign attribute changes)
- `25 – 49.9`: **Moderate** (scoped additions, non-destructive replacements)
- `50 – 74.9`: **High** (recreations, destructive storage operations, broad IAM policies)
- `75 – 100.0`: **Critical** (public SSH/RDP, disabled S3 access blocks, DB deletion)

Overall plan risk is calculated as the maximum resource-level risk score to prevent critical issues from being masked by volume of benign changes.

---

## Detection Rules

### Generic Rules
- `GEN-DEL-001`: Resource deletion in plan.
- `GEN-REP-001`: Resource replacement (destroy and recreate due to immutable attributes).
- `GEN-ACT-001`: Unrecognized or unsupported Terraform lifecycle action sequences.
- `GEN-UNK-001`: Computed unknown values in critical configuration fields.
- `GEN-DST-001`: Destructive changes to stateful resources (databases, volumes, clusters).

### AWS Rules
- `AWS-NET-001`: Security group ingress opening administrative ports (22, 3389) or all traffic to `0.0.0.0/0` or `::/0`.
- `AWS-S3-001`: S3 Public Access Block removal or disabled settings (`block_public_acls`, `block_public_policy`, etc.), or public bucket ACLs.
- `AWS-IAM-001`: Context-sensitive IAM wildcard policies (`*` on `*` is Critical; service-level wildcards on `*` is High).
- `AWS-DB-001`: Deletion or replacement of RDS instances, Aurora clusters, DynamoDB tables, or ElastiCache clusters.

---

## Policy Configuration (`preflight.yaml`)

```yaml
environment: production
format: terminal
fail_on: high

blocked_rules:
  - AWS-DB-001
  - AWS-NET-001

allowed_rules: []

max_score: 75.0
```

---

## Defensive Redaction

Preflight prevents secrets and credentials from appearing in terminal output, CI logs, or pull request comments. The engine recursively redacts:
- Sensitive key names matching password, secret, token, api_key, private_key, or auth patterns.
- Terraform plan attributes flagged via `before_sensitive` and `after_sensitive` metadata.

---

## Verification & Benchmarks

```bash
pytest
pytest --cov=preflight --cov-report=term-missing
ruff check .
ruff format --check .
mypy src tests
python scripts/benchmark.py
```

---

## License

Apache-2.0
