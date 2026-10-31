# Preflight

**Infrastructure change risk analysis and CI/CD safety gate for Terraform execution plans.**

Static linters (`Checkov`, `tfsec`) inspect `.tf` code syntax, but miss runtime state transitions, like an immutable attribute change forcing Terraform to delete and recreate a production database.

**Preflight inspects the actual execution plan graph (`tfplan`)** to catch destructive replacements, quantify blast radius, and block risky deployments before `terraform apply`.

```bash
terraform plan -out=tfplan
terraform show -json tfplan | preflight analyze - --fail-on high
```

* **Zero-Disk Streaming**: Ingest plans via stdin pipe (`analyze -`) so unencrypted plan secrets never touch the runner disk.
* **Deterministic Risk Scoring**: Normalized 5-factor risk model with environment criticality tiers.
* **Multi-Cloud Policy Suite**: Built-in detection rules for AWS, Azure, Google Cloud, Kubernetes, and core Terraform lifecycle actions.
* **CI/CD Native Gate**: Enforces POSIX exit codes (`0` Pass, `1` Block, `2` Error), posts GitHub PR sticky comments, and exports SARIF v2.1.0.

---

## Performance & Quality Metrics

Measured across synthetic benchmarks and automated test suites:

| Metric | Measured Value | Standard |
|---|---|---|
| **Analysis Latency** | **< 0.50 ms** avg per plan | Sub-millisecond static evaluation |
| **Detection Rate** | **100%** (11/11 target scenarios) | Synthetic test fixtures |
| **False Positive Rate** | **0** on control fixtures | Clean control plans produce 0 findings |
| **Test Coverage** | **88%** statement coverage | 105 unit and integration tests |
| **Type Safety** | **100%** strictly typed | `mypy --strict` with zero warnings |
| **Code Quality** | **Zero errors** | Compliant with `ruff` linter and formatter |
| **Scoring Determinism** | **100% bit-for-bit identical** | Zero drift across 50 sequential runs |

---

## Installation

Requires Python 3.12+.

### Recommended: Standalone CLI with `pipx`
Installs `preflight` into an isolated global environment so the binary is directly available in any terminal:

```bash
# Install from PyPI:
pipx install preflight-engine

# Or install directly from GitHub:
pipx install git+https://github.com/adityacodes-root/Preflight.git
```

### With `uv` (Fastest)
```bash
uv tool install preflight-engine
```

### Standard `pip`
```bash
pip install preflight-engine
```

### From Source (Development)
```bash
git clone https://github.com/adityacodes-root/Preflight.git
cd preflight
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

---

## Usage

```bash
# Pipe directly via stdin (recommended for CI/CD)
terraform show -json tfplan | preflight analyze -
terraform show -json tfplan | preflight analyze - --fail-on high

# Publish or update sticky PR comment in CI
terraform show -json tfplan | preflight comment - --fail-on high

# Generate SARIF report for GitHub Code Scanning
terraform show -json tfplan | preflight analyze - --format sarif --output preflight.sarif

# Analyze a local plan file
preflight analyze plan.json
preflight analyze plan.json --fail-on high
preflight analyze plan.json --environment staging
preflight analyze plan.json --format markdown --output report.md
preflight analyze plan.json --format json --output report.json

# Command reference
preflight --help
preflight analyze --help
preflight comment --help
```

### Options

| Option | Flag | Description | Default |
|---|---|---|---|
| `--environment` | `-e` | `development`, `staging`, or `production` | `production` |
| `--format` | `-f` | `terminal`, `json`, `markdown`, or `sarif` | `terminal` |
| `--fail-on` | | Block if findings reach: `low`, `moderate`, `high`, `critical` | *None* |
| `--output` | `-o` | Output file path | stdout |
| `--config` | `-c` | Custom YAML configuration path | `preflight.yaml` |
| `--verbose` | `-v` | Show traceback on error | `false` |
| `--version` | `-V` | Display version | |
| `--help` | | Help and options | |

### Exit Codes

| Code | Status | Meaning |
|:---:|---|---|
| `0` | **Pass** | Analysis completed; no blocking policy conditions triggered. |
| `1` | **Block** | Analysis completed; a configured policy threshold was met. |
| `2` | **Error** | File not found, invalid JSON syntax, or bad configuration. |

---

## CI/CD & GitHub Integration

Preflight integrates directly into CI/CD pipelines to automate infrastructure risk gates and pull request reviews.

### Pull Request Sticky Comments (`preflight comment`)
Posts an infrastructure risk analysis directly to active pull requests. Subsequent commits update the comment in place to prevent notification noise. Repository, token, and PR number are resolved automatically from environment variables (`GITHUB_REPOSITORY`, `GITHUB_TOKEN`, and `GITHUB_REF`).

```bash
# In GitHub Actions
terraform show -json tfplan | preflight comment - --fail-on high

# Local test or manual invocation
preflight comment plan.json --repo owner/repo --pr 42 --token $GITHUB_TOKEN --dry-run
```

### SARIF Code Scanning (`--format sarif`)
Exports findings in OASIS SARIF v2.1.0 to surface inline risk annotations in GitHub Code Scanning, GitLab Security Dashboards, or Azure DevOps.

```bash
terraform show -json tfplan | preflight analyze - --format sarif --output preflight.sarif
```

See [.github/workflows/terraform-pr-check.yml](.github/workflows/terraform-pr-check.yml) for a complete GitHub Actions workflow.

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
- `75 – 100.0`: **Critical** (public SSH/RDP, disabled S3 access blocks, production DB deletion)

Overall plan risk is driven by the highest-risk resource to prevent critical issues from being masked by a large volume of benign changes. When a resource triggers multiple rules, the dominant finding sets the baseline, while secondary findings contribute diminishing increments to avoid artificial score inflation.

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

### Azure Rules
- `AZR-NET-001`: Network Security Group (NSG) rules allowing `0.0.0.0/0` or `Internet` to ports 22, 3389, or wildcard `*`.
- `AZR-STG-001`: Storage account public blob access or missing firewall restrictions.
- `AZR-KV-001`: Azure Key Vault changes with `purge_protection_enabled = false` or soft delete retention < 7 days.
- `AZR-DB-001`: Deletion or replacement of Azure SQL, Cosmos DB, or PostgreSQL flexible servers.

### Google Cloud Rules
- `GCP-FW-001`: Ingress compute firewall rules allowing `0.0.0.0/0` or `::/0` to sensitive administrative ports (22, 3389) or all traffic.
- `GCP-IAM-001`: Cloud Storage bucket IAM bindings or members granting access to `allUsers` or `allAuthenticatedUsers`.
- `GCP-SQL-001`: Cloud SQL instance deletion, replacement, or disabling `deletion_protection`.

### Kubernetes Rules
- `K8S-SEC-001`: Workloads or Helm charts deploying with `security_context.privileged: true` or `hostNetwork: true`.
- `K8S-RBAC-001`: RoleBindings and ClusterRoleBindings binding to superuser role `cluster-admin`.

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
