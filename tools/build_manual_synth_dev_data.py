"""Build the manually curated developer/data NL-to-Bash training shard.

The examples are generated from hand-written, semantically reviewed command
families and a fixed set of realistic project contexts.  This is deliberately
deterministic: it does not call a model, an API, or a random text generator.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "manual_synth_dev_data.json"


CONTEXTS = [
    dict(repo="api-gateway", org="acme", branch="feature/rate-limit", base="main", tag="v2.4.1", sha="a13f9c2", oldsha="HEAD@{7}", dir="services/api", file="src/server.py", test="tests/test_api.py", pkg="requests", crate="serde", module="example.com/acme/gateway", image="ghcr.io/acme/api:2.4.1", db="gateway", table="requests", topic="api-events", group="gateway-workers", key="cache:user:1042", bucket="s3:acme-backups/gateway", remote="backup", pattern="timeout", field="status", column="latency_ms", port="8080"),
    dict(repo="billing-worker", org="northwind", branch="fix/retry-jitter", base="develop", tag="v1.8.0", sha="b74e0ad", oldsha="HEAD@{12}", dir="workers/billing", file="src/retry.rs", test="tests/retry_test.rs", pkg="tokio", crate="anyhow", module="corp.example/billing", image="registry.example.com/billing:1.8.0", db="billing", table="invoices", topic="invoice-events", group="billing-consumers", key="job:invoice:8821", bucket="s3:northwind-archive/billing", remote="archive", pattern="retry exhausted", field="amount", column="customer_id", port="9092"),
    dict(repo="frontend-portal", org="contoso", branch="chore/vite-upgrade", base="main", tag="release-2026.07", sha="c9128ef", oldsha="HEAD@{3}", dir="apps/portal", file="src/routes.ts", test="test/routes.test.ts", pkg="typescript", crate="clap", module="git.example/portal/tools", image="ghcr.io/contoso/portal:2026.07", db="portal", table="sessions", topic="ui-telemetry", group="analytics-reader", key="session:9f2c", bucket="s3:contoso-data/portal", remote="coldstore", pattern="deprecated", field="user_id", column="created_at", port="3000"),
    dict(repo="analytics-pipeline", org="dataworks", branch="feature/parquet-v2", base="trunk", tag="2026.07.3", sha="d338ab1", oldsha="HEAD@{21}", dir="pipelines/events", file="jobs/normalize.py", test="tests/test_normalize.py", pkg="pyarrow", crate="polars", module="internal.example/analytics", image="registry.example.com/analytics:2026.07.3", db="analytics", table="events", topic="raw-events", group="normalizer-v2", key="offset:events:17", bucket="s3:data-lake/raw/events", remote="datalake", pattern="schema mismatch", field="event_type", column="event_time", port="5432"),
    dict(repo="mobile-backend", org="fabrikam", branch="feature/push-receipts", base="main", tag="v5.0.0-rc2", sha="e15c774", oldsha="HEAD@{9}", dir="services/mobile", file="internal/push/receipt.go", test="internal/push/receipt_test.go", pkg="cobra", crate="reqwest", module="example.net/mobile/backend", image="ghcr.io/fabrikam/mobile:5.0.0-rc2", db="mobile", table="devices", topic="push-receipts", group="receipt-handler", key="device:a81b", bucket="s3:fabrikam-backup/mobile", remote="vault", pattern="invalid token", field="platform", column="last_seen", port="6379"),
    dict(repo="search-indexer", org="globex", branch="perf/bulk-index", base="main", tag="v3.6.4", sha="f509dc8", oldsha="HEAD@{15}", dir="services/indexer", file="src/main/java/SearchJob.java", test="src/test/java/SearchJobTest.java", pkg="pydantic", crate="rayon", module="code.example/search/indexer", image="registry.example.com/search-indexer:3.6.4", db="search", table="documents", topic="document-updates", group="search-indexers", key="index:document:771", bucket="s3:globex-snapshots/search", remote="snapshots", pattern="bulk rejected", field="document_id", column="indexed_at", port="9200"),
    dict(repo="identity-service", org="initech", branch="security/key-rotation", base="main", tag="v4.2.2", sha="0ab71de", oldsha="HEAD@{5}", dir="services/identity", file="src/Auth/TokenService.cs", test="tests/Auth.Tests/TokenServiceTests.cs", pkg="cryptography", crate="jsonwebtoken", module="git.corp/identity/service", image="ghcr.io/initech/identity:4.2.2", db="identity", table="accounts", topic="auth-audit", group="audit-sink", key="token:blacklist:31", bucket="s3:initech-secure/identity", remote="secure", pattern="signature failed", field="account_id", column="locked_at", port="8443"),
    dict(repo="notification-hub", org="umbrella", branch="fix/email-batching", base="develop", tag="v0.19.5", sha="1c409fb", oldsha="HEAD@{18}", dir="services/notify", file="lib/mailer.js", test="test/mailer.spec.js", pkg="eslint", crate="lettre", module="example.org/notify/hub", image="registry.example.com/notify:0.19.5", db="notifications", table="deliveries", topic="email-jobs", group="email-senders", key="delivery:queued:45", bucket="s3:umbrella-logs/notify", remote="logs", pattern="smtp refused", field="recipient", column="sent_at", port="2525"),
    dict(repo="inventory-sync", org="soylent", branch="feature/delta-import", base="main", tag="v7.1.0", sha="2d8f6a0", oldsha="HEAD@{11}", dir="jobs/inventory", file="cmd/sync/main.go", test="cmd/sync/main_test.go", pkg="pytest", crate="csv", module="example.com/soylent/inventory", image="ghcr.io/soylent/inventory:7.1.0", db="inventory", table="stock_items", topic="stock-changes", group="inventory-sync", key="sku:WH4:109", bucket="s3:soylent-exports/inventory", remote="exports", pattern="negative quantity", field="sku", column="warehouse_id", port="3306"),
    dict(repo="reporting-engine", org="stark", branch="feature/pdf-a11y", base="main", tag="v2.11.3", sha="3ef201c", oldsha="HEAD@{6}", dir="services/reporting", file="src/report/render.py", test="tests/test_render.py", pkg="jinja2", crate="printpdf", module="git.example/stark/reporting", image="registry.example.com/reporting:2.11.3", db="reporting", table="reports", topic="report-ready", group="report-publishers", key="report:pending:930", bucket="s3:stark-reports/archive", remote="reports", pattern="font missing", field="format", column="generated_at", port="9000"),
    dict(repo="edge-proxy", org="wayne", branch="fix/http3-timeout", base="trunk", tag="v6.3.1", sha="4a63e9b", oldsha="HEAD@{14}", dir="infra/edge", file="src/proxy/config.rs", test="tests/proxy_config.rs", pkg="httpx", crate="hyper", module="corp.example/edge/proxy", image="ghcr.io/wayne/edge-proxy:6.3.1", db="edge", table="routes", topic="proxy-metrics", group="metrics-exporter", key="route:api:v3", bucket="s3:wayne-edge/config", remote="edgeconfig", pattern="upstream reset", field="route_id", column="priority", port="443"),
    dict(repo="ml-feature-store", org="wonka", branch="feature/ttl-policy", base="main", tag="v1.12.0", sha="5bd704e", oldsha="HEAD@{24}", dir="platform/features", file="feature_store/materialize.py", test="tests/test_materialize.py", pkg="pandas", crate="arrow", module="example.io/ml/features", image="registry.example.com/feature-store:1.12.0", db="features", table="feature_values", topic="feature-updates", group="materializers", key="feature:customer_age:v2", bucket="s3:wonka-ml/features", remote="featurelake", pattern="stale feature", field="entity_id", column="expires_at", port="7000"),
    dict(repo="audit-collector", org="hooli", branch="feature/otlp-export", base="main", tag="v0.8.7", sha="6c2a815", oldsha="HEAD@{4}", dir="agents/audit", file="collector/exporter.go", test="collector/exporter_test.go", pkg="opentelemetry-api", crate="tracing", module="git.hooli.dev/audit/collector", image="ghcr.io/hooli/audit-collector:0.8.7", db="audit", table="audit_log", topic="security-audit", group="audit-archive", key="audit:cursor:eu1", bucket="s3:hooli-compliance/audit", remote="compliance", pattern="export failed", field="actor", column="occurred_at", port="4317"),
    dict(repo="order-orchestrator", org="massive-dynamic", branch="fix/saga-compensation", base="develop", tag="v9.4.0", sha="7de9183", oldsha="HEAD@{19}", dir="services/orders", file="src/saga/orchestrator.ts", test="test/saga/orchestrator.test.ts", pkg="zod", crate="sqlx", module="example.com/orders/orchestrator", image="registry.example.com/orders:9.4.0", db="orders", table="order_steps", topic="order-state", group="saga-coordinators", key="order:saga:5582", bucket="s3:orders-dr/archive", remote="disaster", pattern="compensation failed", field="order_id", column="step_state", port="5672"),
    dict(repo="catalog-api", org="vehement", branch="feature/faceted-search", base="main", tag="v3.0.6", sha="8f4b2c9", oldsha="HEAD@{8}", dir="services/catalog", file="app/catalog/query.py", test="tests/catalog/test_query.py", pkg="fastapi", crate="axum", module="git.example/catalog/api", image="ghcr.io/vehement/catalog:3.0.6", db="catalog", table="products", topic="catalog-changes", group="catalog-cache", key="product:facet:blue", bucket="s3:catalog-assets/archive", remote="assets", pattern="facet unavailable", field="category", column="updated_at", port="8000"),
    dict(repo="payments-ledger", org="oscorp", branch="security/idempotency", base="main", tag="v8.2.5", sha="91a5d30", oldsha="HEAD@{27}", dir="services/ledger", file="src/Ledger/Posting.cs", test="tests/Ledger.Tests/PostingTests.cs", pkg="sqlalchemy", crate="rust_decimal", module="corp.example/payments/ledger", image="registry.example.com/ledger:8.2.5", db="ledger", table="postings", topic="ledger-posted", group="settlement-writer", key="payment:idempotency:4ab", bucket="s3:oscorp-ledger/worm", remote="worm", pattern="unbalanced posting", field="currency", column="posted_at", port="6432"),
    dict(repo="telemetry-agent", org="cyberdyne", branch="perf/cardinality-limit", base="trunk", tag="v1.3.9", sha="a257e64", oldsha="HEAD@{10}", dir="agents/telemetry", file="src/metrics/cardinality.rs", test="tests/cardinality.rs", pkg="prometheus-client", crate="metrics", module="example.net/telemetry/agent", image="ghcr.io/cyberdyne/telemetry:1.3.9", db="telemetry", table="metric_points", topic="host-metrics", group="metric-ingest", key="metric:cardinality:host", bucket="s3:telemetry-raw/metrics", remote="metrics", pattern="cardinality exceeded", field="metric_name", column="sample_time", port="9090"),
    dict(repo="content-service", org="tyrell", branch="feature/revision-diff", base="main", tag="v2.7.8", sha="b390fd7", oldsha="HEAD@{16}", dir="services/content", file="src/revisions/diff.js", test="test/revisions/diff.test.js", pkg="prettier", crate="similar", module="git.tyrell.example/content", image="registry.example.com/content:2.7.8", db="content", table="revisions", topic="content-published", group="search-update", key="revision:page:440", bucket="s3:tyrell-content/versions", remote="versions", pattern="revision conflict", field="author_id", column="published_at", port="4000"),
    dict(repo="fraud-detector", org="gringotts", branch="feature/rule-explanations", base="main", tag="v4.6.0", sha="c48e123", oldsha="HEAD@{13}", dir="models/fraud", file="src/rules/explain.py", test="tests/rules/test_explain.py", pkg="scikit-learn", crate="ndarray", module="example.org/fraud/detector", image="ghcr.io/gringotts/fraud:4.6.0", db="fraud", table="decisions", topic="fraud-scores", group="decision-engine", key="rule:velocity:7d", bucket="s3:fraud-models/releases", remote="models", pattern="rule timeout", field="decision", column="risk_score", port="8501"),
    dict(repo="shipping-planner", org="oceanic", branch="fix/timezone-cutoff", base="develop", tag="v5.7.2", sha="d57af80", oldsha="HEAD@{22}", dir="services/shipping", file="planner/cutoff.go", test="planner/cutoff_test.go", pkg="pendulum", crate="chrono", module="git.example/shipping/planner", image="registry.example.com/shipping:5.7.2", db="shipping", table="shipments", topic="shipment-planned", group="carrier-dispatch", key="shipment:plan:1203", bucket="s3:oceanic-manifests/archive", remote="manifests", pattern="cutoff missed", field="carrier", column="ship_date", port="8088"),
    dict(repo="config-controller", org="black-mesa", branch="feature/schema-v3", base="main", tag="v3.3.3", sha="e602ab4", oldsha="HEAD@{2}", dir="controllers/config", file="pkg/schema/validate.go", test="pkg/schema/validate_test.go", pkg="jsonschema", crate="schemars", module="example.com/config/controller", image="ghcr.io/black-mesa/config-controller:3.3.3", db="configuration", table="config_versions", topic="config-applied", group="config-watchers", key="config:schema:v3", bucket="s3:blackmesa-config/history", remote="configstore", pattern="validation failed", field="schema_version", column="applied_at", port="9443"),
    dict(repo="recommendation-api", org="vandelay", branch="perf/vector-cache", base="main", tag="v1.5.4", sha="f71c9d2", oldsha="HEAD@{17}", dir="services/recommendation", file="src/cache/vector.py", test="tests/cache/test_vector.py", pkg="numpy", crate="faiss", module="corp.example/recommendation/api", image="registry.example.com/recommendation:1.5.4", db="recommendations", table="candidate_scores", topic="ranking-events", group="rankers", key="vector:user:772", bucket="s3:vandelay-features/vectors", remote="vectors", pattern="embedding missing", field="candidate_id", column="score", port="5000"),
    dict(repo="document-processor", org="paper-street", branch="feature/ocr-layout", base="trunk", tag="v0.14.2", sha="07bd5e6", oldsha="HEAD@{20}", dir="workers/documents", file="processor/layout.py", test="tests/test_layout.py", pkg="pytesseract", crate="lopdf", module="example.io/documents/processor", image="ghcr.io/paper-street/document-processor:0.14.2", db="documents", table="pages", topic="document-pages", group="ocr-workers", key="document:page:182", bucket="s3:paperstreet-docs/incoming", remote="documents", pattern="ocr confidence low", field="page_number", column="confidence", port="8081"),
    dict(repo="scheduler-core", org="prestige", branch="fix/overlap-lock", base="main", tag="v6.9.1", sha="18ce473", oldsha="HEAD@{23}", dir="platform/scheduler", file="src/jobs/lock.ts", test="test/jobs/lock.test.ts", pkg="vitest", crate="uuid", module="git.example/scheduler/core", image="registry.example.com/scheduler:6.9.1", db="scheduler", table="job_runs", topic="job-events", group="scheduler-executors", key="job:lock:nightly", bucket="s3:prestige-scheduler/history", remote="history", pattern="overlap prevented", field="job_name", column="started_at", port="7233"),
]


SPECS: list[tuple[str, str, str, str]] = [
    # Advanced Git: worktrees, bisect, reflog, submodules, sparse/partial clones.
    ("git-worktree", "caution", "Create a linked worktree for <repo> on branch <branch>", "git -C <repo> worktree add ../<repo>-worktree <branch>"),
    ("git-worktree", "safe", "List <repo> worktrees in machine-readable porcelain format", "git -C <repo> worktree list --porcelain"),
    ("git-worktree", "caution", "Create a detached worktree for <repo> at tag <tag>", "git -C <repo> worktree add --detach ../<repo>-<tag> <tag>"),
    ("git-worktree", "caution", "Lock the <repo> linked worktree and record that it is used by automation", "git -C <repo> worktree lock --reason 'used by automation' ../<repo>-worktree"),
    ("git-worktree", "caution", "Move the linked <repo> worktree to a new local path", "git -C <repo> worktree move ../<repo>-worktree ../<repo>-review"),
    ("git-worktree", "destructive", "Remove the linked <repo> review worktree", "git -C <repo> worktree remove ../<repo>-review"),
    ("git-worktree", "safe", "Preview stale worktree metadata that Git would prune in <repo>", "git -C <repo> worktree prune --dry-run --verbose"),
    ("git-bisect", "caution", "Begin a bisect in <repo> using <base> as good and <tag> as bad", "git -C <repo> bisect start <tag> <base>"),
    ("git-bisect", "caution", "Have git bisect in <repo> run the focused test <test>", "git -C <repo> bisect run ./scripts/run-one-test.sh <test>"),
    ("git-bisect", "caution", "Skip commit <sha> during the active bisect in <repo>", "git -C <repo> bisect skip <sha>"),
    ("git-bisect", "caution", "End the current bisect session in <repo>", "git -C <repo> bisect reset"),
    ("git-reflog", "safe", "Show the <repo> reflog with ISO timestamps and abbreviated hashes", "git -C <repo> reflog show --date=iso --format='%h %gd %cd %gs'"),
    ("git-reflog", "caution", "Recover <repo> state <oldsha> into a new branch named recover-<sha>", "git -C <repo> branch recover-<sha> '<oldsha>'"),
    ("git-reflog", "safe", "Inspect the commit referenced by <oldsha> in <repo> without changing files", "git -C <repo> show --stat --oneline '<oldsha>'"),
    ("git-reflog", "safe", "Show reflog entries for branch <branch> in <repo>", "git -C <repo> reflog show '<branch>' --date=relative"),
    ("git-submodule", "caution", "Add <org>/<repo> as a submodule under vendor/<repo>", "git submodule add https://github.com/<org>/<repo>.git vendor/<repo>"),
    ("git-submodule", "caution", "Initialize and update all nested submodules in <repo> with shallow history", "git -C <repo> submodule update --init --recursive --depth 1"),
    ("git-submodule", "safe", "Show recursive submodule status for <repo>", "git -C <repo> submodule status --recursive"),
    ("git-submodule", "caution", "Synchronize changed submodule URLs recursively in <repo>", "git -C <repo> submodule sync --recursive"),
    ("git-submodule", "caution", "Set submodule vendor/<repo> to track branch <base>", "git submodule set-branch --branch <base> vendor/<repo>"),
    ("git-submodule", "caution", "Move embedded submodule Git directories into the <repo> superproject", "git -C <repo> submodule absorbgitdirs"),
    ("git-sparse", "caution", "Initialize cone-mode sparse checkout in <repo>", "git -C <repo> sparse-checkout init --cone"),
    ("git-sparse", "caution", "Restrict the <repo> sparse checkout to <dir>", "git -C <repo> sparse-checkout set <dir>"),
    ("git-sparse", "safe", "List the sparse-checkout paths configured in <repo>", "git -C <repo> sparse-checkout list"),
    ("git-history", "safe", "Find commits in <repo> that changed occurrences of <pattern> in <file>", "git -C <repo> log -S '<pattern>' --oneline -- <file>"),
    ("git-history", "safe", "Find commits in <repo> whose patch matches regex <pattern>", "git -C <repo> log -G '<pattern>' --oneline --all"),
    ("git-history", "safe", "Show which commit and author last changed each line of <file> in <repo>", "git -C <repo> blame --date=short <file>"),
    ("git-history", "safe", "Compare branch <branch> against its merge base with <base> in <repo>", "git -C <repo> diff '<base>...<branch>'"),
    ("git-maintenance", "safe", "Verify all reachable Git objects in <repo>", "git -C <repo> fsck --full --no-dangling"),
    ("git-maintenance", "caution", "Run incremental repository maintenance for <repo>", "git -C <repo> maintenance run --task=incremental-repack"),

    # GitHub and GitLab command-line clients.
    ("github-cli", "safe", "List open pull requests for <org>/<repo> as JSON", "gh pr list --repo <org>/<repo> --state open --json number,title,author,headRefName"),
    ("github-cli", "safe", "List failed GitHub Actions runs for <org>/<repo> on branch <branch>", "gh run list --repo <org>/<repo> --branch '<branch>' --status failure"),
    ("github-cli", "safe", "Show only failed-step logs from the latest run for <org>/<repo>", "gh run view \"$(gh run list --repo <org>/<repo> --limit 1 --json databaseId --jq '.[0].databaseId')\" --repo <org>/<repo> --log-failed"),
    ("github-cli", "caution", "Dispatch the ci workflow for <org>/<repo> on branch <branch>", "gh workflow run ci.yml --repo <org>/<repo> --ref '<branch>'"),
    ("github-cli", "safe", "Query every release tag for <org>/<repo> through the paginated GitHub API", "gh api --paginate repos/<org>/<repo>/releases --jq '.[].tag_name'"),
    ("github-cli", "caution", "Create a draft pull request from <branch> to <base> in <org>/<repo>", "gh pr create --repo <org>/<repo> --base '<base>' --head '<branch>' --draft --fill"),
    ("github-cli", "caution", "Download all assets from release <tag> of <org>/<repo>", "gh release download '<tag>' --repo <org>/<repo> --dir releases/<repo>/<tag>"),
    ("github-cli", "safe", "List repository secrets configured for <org>/<repo>", "gh secret list --repo <org>/<repo>"),
    ("github-cli", "safe", "List Dependabot alerts for <org>/<repo> with package and severity", "gh api repos/<org>/<repo>/dependabot/alerts --jq '.[] | [.dependency.package.name,.security_advisory.severity] | @tsv'"),
    ("github-cli", "safe", "Show open issues labeled bug in <org>/<repo>", "gh issue list --repo <org>/<repo> --state open --label bug --limit 100"),
    ("gitlab-cli", "safe", "List open merge requests for <org>/<repo> with the GitLab CLI", "glab mr list --repo <org>/<repo> --state opened"),
    ("gitlab-cli", "safe", "Show the CI pipeline for branch <branch> in <org>/<repo>", "glab ci status --repo <org>/<repo> --branch '<branch>'"),
    ("gitlab-cli", "caution", "Create a draft GitLab merge request from <branch> to <base>", "glab mr create --repo <org>/<repo> --source-branch '<branch>' --target-branch '<base>' --draft --fill"),
    ("gitlab-cli", "safe", "Download build artifacts from branch <branch> of <org>/<repo>", "glab ci artifact '<branch>' build --repo <org>/<repo>"),
    ("gitlab-cli", "caution", "Run a GitLab CI pipeline for <org>/<repo> on <branch>", "glab ci run --repo <org>/<repo> --branch '<branch>'"),
    ("gitlab-cli", "safe", "List project releases for <org>/<repo> through the GitLab API", "glab api projects/<org>%2F<repo>/releases --paginate | jq -r '.[].tag_name'"),
    ("gitlab-cli", "safe", "List open GitLab issues assigned to the current user in <org>/<repo>", "glab issue list --repo <org>/<repo> --assignee=@me --state opened"),
    ("gitlab-cli", "caution", "Create GitLab release <tag> for <org>/<repo> from its matching tag", "glab release create '<tag>' --repo <org>/<repo> --ref '<tag>' --notes-from-tag"),

    # Rust, Go, Node, Python, Java and .NET development tooling.
    ("rust-tooling", "safe", "Check all targets and features in Rust project <repo> without building artifacts", "cargo check --manifest-path <repo>/Cargo.toml --all-targets --all-features"),
    ("rust-tooling", "safe", "Run Clippy for every target in <repo> and treat warnings as errors", "cargo clippy --manifest-path <repo>/Cargo.toml --all-targets --all-features -- -D warnings"),
    ("rust-tooling", "safe", "Run Rust tests matching <pattern> in <repo> and show captured output", "cargo test --manifest-path <repo>/Cargo.toml '<pattern>' -- --nocapture"),
    ("rust-tooling", "caution", "Update only crate <crate> to a compatible locked version in <repo>", "cargo update --manifest-path <repo>/Cargo.toml -p <crate>"),
    ("rust-tooling", "safe", "Display the inverse Cargo dependency tree for <crate> in <repo>", "cargo tree --manifest-path <repo>/Cargo.toml --invert <crate>"),
    ("rust-tooling", "safe", "Find duplicate crate versions in the <repo> dependency graph", "cargo tree --manifest-path <repo>/Cargo.toml --duplicates"),
    ("rust-tooling", "safe", "Build optimized Rust binaries for <repo> with locked dependencies", "cargo build --manifest-path <repo>/Cargo.toml --release --locked"),
    ("go-tooling", "safe", "Run all Go tests under module <module> with the race detector", "cd <repo> && go test -race ./..."),
    ("go-tooling", "safe", "Explain why the Go project <repo> depends on golang.org/x/sync", "cd <repo> && go mod why -m golang.org/x/sync"),
    ("go-tooling", "caution", "Tidy the Go module files for <repo> and report changes", "cd <repo> && go mod tidy -v"),
    ("go-tooling", "safe", "Verify downloaded Go module content for <repo>", "cd <repo> && go mod verify"),
    ("go-tooling", "safe", "Show available updates for direct Go dependencies in <repo>", "cd <repo> && go list -m -u all"),
    ("go-tooling", "safe", "Profile benchmark allocations for package <dir> in <repo>", "cd <repo> && go test -bench=. -benchmem ./<dir>"),
    ("go-tooling", "caution", "Install the Go command from module <module> at tag <tag>", "go install <module>@<tag>"),
    ("node-tooling", "safe", "Install the exact locked Node dependencies for <repo> without audit network calls", "npm ci --prefix <repo> --ignore-scripts --no-audit"),
    ("node-tooling", "safe", "Explain why npm package <pkg> is installed in <repo>", "npm explain <pkg> --prefix <repo>"),
    ("node-tooling", "safe", "List outdated direct npm dependencies for <repo>", "npm outdated --prefix <repo> --depth=0"),
    ("node-tooling", "safe", "Run the <repo> test script against <test>", "npm test --prefix <repo> -- <test>"),
    ("node-tooling", "safe", "Show all published versions of npm package <pkg> as JSON", "npm view <pkg> versions --json"),
    ("node-tooling", "safe", "Audit production npm dependencies in <repo> at high severity", "npm audit --prefix <repo> --omit=dev --audit-level=high"),
    ("node-tooling", "caution", "Use Corepack to activate the package-manager version declared by <repo>", "cd <repo> && corepack install"),
    ("python-tooling", "safe", "Create an isolated Python virtual environment for <repo>", "python -m venv <repo>/.venv"),
    ("python-tooling", "safe", "Install <repo> with development extras in editable mode", "<repo>/.venv/bin/python -m pip install -e '<repo>[dev]'"),
    ("python-tooling", "safe", "Display the installed dependency tree for package <pkg> in <repo>", "<repo>/.venv/bin/python -m pipdeptree -p <pkg>"),
    ("python-tooling", "safe", "Check <repo> installed packages for incompatible requirements", "<repo>/.venv/bin/python -m pip check"),
    ("python-tooling", "safe", "Run Python test <test> in <repo> with durations for slow tests", "<repo>/.venv/bin/python -m pytest <repo>/<test> --durations=10"),
    ("python-tooling", "safe", "Type-check <file> in <repo> with strict mypy rules", "<repo>/.venv/bin/python -m mypy --strict <repo>/<file>"),
    ("python-tooling", "caution", "Build both wheel and source distributions for <repo>", "cd <repo> && .venv/bin/python -m build --wheel --sdist"),
    ("python-tooling", "safe", "Download a binary wheel for <pkg> without installing it", "python -m pip download --no-deps --only-binary=:all: <pkg> -d /tmp/<repo>-wheels"),
    ("java-tooling", "safe", "Run Maven tests matching <test> in <repo>", "mvn -f <repo>/pom.xml -Dtest=<test> test"),
    ("java-tooling", "safe", "Show the Maven dependency tree filtered to <pkg> for <repo>", "mvn -f <repo>/pom.xml dependency:tree -Dincludes=<pkg>"),
    ("java-tooling", "safe", "Check <repo> for newer Maven dependency versions without changing the POM", "mvn -f <repo>/pom.xml versions:display-dependency-updates"),
    ("java-tooling", "safe", "Build <repo> with Gradle using the checked-in wrapper and no daemon", "<repo>/gradlew -p <repo> build --no-daemon"),
    ("java-tooling", "safe", "Explain the selected Gradle version of dependency <pkg> in <repo>", "<repo>/gradlew -p <repo> dependencyInsight --dependency <pkg>"),
    ("java-tooling", "safe", "Run one Gradle test class <test> in <repo>", "<repo>/gradlew -p <repo> test --tests '<test>'"),
    ("dotnet-tooling", "safe", "Restore locked NuGet dependencies for <repo>", "dotnet restore <repo> --locked-mode"),
    ("dotnet-tooling", "safe", "Run the .NET tests in <repo> matching <test>", "dotnet test <repo> --filter 'FullyQualifiedName~<test>' --no-restore"),
    ("dotnet-tooling", "safe", "List vulnerable transitive NuGet packages in <repo>", "dotnet list <repo> package --vulnerable --include-transitive"),
    ("dotnet-tooling", "safe", "List outdated NuGet packages in <repo>", "dotnet list <repo> package --outdated"),
    ("dotnet-tooling", "caution", "Add Serilog version 4.3.0 to the .NET project <repo>", "dotnet add <repo> package Serilog --version 4.3.0"),
    ("dotnet-tooling", "safe", "Publish <repo> as a trimmed self-contained Linux x64 build", "dotnet publish <repo> -c Release -r linux-x64 --self-contained true -p:PublishTrimmed=true"),

    # Build systems and binary/package inspection.
    ("build-systems", "safe", "Build all configured targets in <repo> with Ninja and verbose commands", "ninja -C <repo>/build -v all"),
    ("build-systems", "caution", "Configure <repo> with CMake and export compile commands", "cmake -S <repo> -B <repo>/build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"),
    ("build-systems", "safe", "Run only CTest cases matching <test> in <repo> and show failures", "ctest --test-dir <repo>/build -R '<test>' --output-on-failure"),
    ("build-systems", "safe", "Query Bazel targets below <dir> in <repo>", "cd <repo> && bazel query '//<dir>/...'"),
    ("build-systems", "safe", "Test the Bazel target <dir> in <repo> with uncached output", "cd <repo> && bazel test '//<dir>:all' --test_output=errors --nocache_test_results"),
    ("build-systems", "safe", "Build all configured Meson targets in <repo>", "meson compile -C <repo>/build"),
    ("package-inspection", "safe", "List files contained in Debian package <repo>.deb", "dpkg-deb --contents <repo>.deb"),
    ("package-inspection", "safe", "Show metadata from Debian package <repo>.deb", "dpkg-deb --info <repo>.deb"),
    ("package-inspection", "safe", "List files contained in RPM package <repo>.rpm", "rpm -qlp <repo>.rpm"),
    ("package-inspection", "safe", "Show scripts embedded in RPM package <repo>.rpm", "rpm -qp --scripts <repo>.rpm"),
    ("binary-inspection", "safe", "Display dynamic library dependencies of <repo>/bin/<repo>", "ldd <repo>/bin/<repo>"),
    ("binary-inspection", "safe", "List undefined dynamic symbols in <repo>/bin/<repo>", "nm -D --undefined-only <repo>/bin/<repo>"),
    ("binary-inspection", "safe", "Show ELF headers and program headers for <repo>/bin/<repo>", "readelf -h -l <repo>/bin/<repo>"),
    ("binary-inspection", "safe", "Disassemble the text section of <repo>/bin/<repo> with Intel syntax", "objdump -d -M intel --section=.text <repo>/bin/<repo>"),

    # PostgreSQL, MySQL/MariaDB, SQLite, Redis and Kafka.
    ("postgresql", "safe", "List the largest relations in PostgreSQL database <db>", "psql -d <db> -X -v ON_ERROR_STOP=1 -c \"SELECT schemaname,relname,pg_size_pretty(pg_total_relation_size(relid)) FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 20;\""),
    ("postgresql", "safe", "Export <table> from PostgreSQL database <db> as CSV with a header", "psql -d <db> -X -v ON_ERROR_STOP=1 -c \"\\copy <table> TO '<repo>-<table>.csv' WITH (FORMAT csv, HEADER true)\""),
    ("postgresql", "safe", "Explain and execute an indexed lookup on <column> in <db> table <table>", "psql -d <db> -X -c \"EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM <table> WHERE <column> IS NOT NULL LIMIT 100;\""),
    ("postgresql", "safe", "Dump only the schema of PostgreSQL database <db>", "pg_dump --dbname=<db> --schema-only --no-owner --no-privileges > <db>-schema.sql"),
    ("postgresql", "safe", "Create a compressed custom-format backup of PostgreSQL database <db>", "pg_dump --dbname=<db> --format=custom --compress=9 --file=<db>-<tag>.dump"),
    ("postgresql", "caution", "Restore table <table> from a PostgreSQL custom dump into <db>", "pg_restore --dbname=<db> --table=<table> --single-transaction --exit-on-error <db>-<tag>.dump"),
    ("postgresql", "safe", "Show currently active PostgreSQL queries in database <db>", "psql -d <db> -X -c \"SELECT pid,usename,wait_event_type,query_start,query FROM pg_stat_activity WHERE state='active';\""),
    ("postgresql", "caution", "Reindex PostgreSQL table <table> concurrently in database <db>", "psql -d <db> -X -v ON_ERROR_STOP=1 -c \"REINDEX TABLE CONCURRENTLY <table>;\""),
    ("mysql", "safe", "Dump only table <table> from MySQL database <db> in a transaction", "mysqldump --single-transaction --quick --skip-lock-tables <db> <table> > <db>-<table>.sql"),
    ("mysql", "safe", "Dump the schema without rows from MySQL database <db>", "mysqldump --no-data --routines --triggers <db> > <db>-schema.sql"),
    ("mysql", "safe", "List the largest tables in MySQL schema <db>", "mysql --database=<db> --batch --raw -e \"SELECT table_name, data_length+index_length AS bytes FROM information_schema.tables WHERE table_schema='<db>' ORDER BY bytes DESC LIMIT 20;\""),
    ("mysql", "safe", "Show the query plan for filtering <table> rows with non-null <column> in <db>", "mysql --database=<db> --table -e \"EXPLAIN SELECT * FROM <table> WHERE <column> IS NOT NULL LIMIT 100;\""),
    ("mysql", "caution", "Import <table> SQL into MySQL database <db>", "mysql --database=<db> --show-warnings < <db>-<table>.sql"),
    ("sqlite", "safe", "Export SQLite table <table> from <db>.sqlite as CSV with headers", "sqlite3 -header -csv <db>.sqlite \"SELECT * FROM <table>;\" > <db>-<table>.csv"),
    ("sqlite", "safe", "Run an integrity check on SQLite database <db>.sqlite", "sqlite3 <db>.sqlite 'PRAGMA integrity_check;'"),
    ("sqlite", "safe", "Show the query plan for a <column> lookup in SQLite table <table>", "sqlite3 <db>.sqlite \"EXPLAIN QUERY PLAN SELECT * FROM <table> WHERE <column> IS NOT NULL;\""),
    ("sqlite", "safe", "Create a consistent backup of SQLite database <db>.sqlite", "sqlite3 <db>.sqlite \".backup '<db>-<tag>.sqlite'\""),
    ("sqlite", "caution", "Compact SQLite database <db>.sqlite into a new file", "sqlite3 <db>.sqlite \"VACUUM INTO '<db>-compact.sqlite';\""),
    ("redis", "safe", "Scan Redis keys matching the namespace of <key> without blocking the server", "redis-cli --scan --pattern '<key>*' --count 500"),
    ("redis", "safe", "Show the type and remaining TTL of Redis key <key>", "redis-cli --raw TYPE '<key>' && redis-cli --raw TTL '<key>'"),
    ("redis", "safe", "Measure memory used by Redis key <key>", "redis-cli --raw MEMORY USAGE '<key>' SAMPLES 5"),
    ("redis", "safe", "Read the newest ten entries from Redis stream <key>", "redis-cli --raw XREVRANGE '<key>' + - COUNT 10"),
    ("redis", "caution", "Set Redis key <key> only if absent with a one-hour expiry", "redis-cli SET '<key>' '<sha>' NX EX 3600"),
    ("kafka", "safe", "Describe Kafka topic <topic> including partitions and replicas", "kafka-topics.sh --bootstrap-server localhost:<port> --describe --topic '<topic>'"),
    ("kafka", "safe", "Show current offsets for Kafka consumer group <group>", "kafka-consumer-groups.sh --bootstrap-server localhost:<port> --describe --group '<group>'"),
    ("kafka", "safe", "Consume the first ten Kafka records from <topic> with timestamps and keys", "kafka-console-consumer.sh --bootstrap-server localhost:<port> --topic '<topic>' --from-beginning --max-messages 10 --property print.timestamp=true --property print.key=true"),
    ("kafka", "caution", "Create Kafka topic <topic> with six partitions and replication factor three", "kafka-topics.sh --bootstrap-server localhost:<port> --create --if-not-exists --topic '<topic>' --partitions 6 --replication-factor 3"),
    ("kafka", "caution", "Reset consumer group <group> for <topic> to the earliest offset after previewing", "kafka-consumer-groups.sh --bootstrap-server localhost:<port> --group '<group>' --topic '<topic>' --reset-offsets --to-earliest --execute"),

    # Structured JSON/YAML plus CSV, Parquet and Arrow tooling.
    ("jq", "safe", "Group the JSON array in <repo>.json by <field> and count each group", "jq 'group_by(.<field>) | map({key: .[0].<field>, count: length})' <repo>.json"),
    ("jq", "safe", "Index objects in <repo>.json by <field>", "jq 'map({key: .<field>, value: .}) | from_entries' <repo>.json"),
    ("jq", "safe", "Recursively remove null-valued object fields from <repo>.json", "jq 'walk(if type == \"object\" then with_entries(select(.value != null)) else . end)' <repo>.json"),
    ("jq", "safe", "Merge every JSON object from directory <dir> with later values taking precedence", "jq -s 'reduce .[] as $item ({}; . * $item)' <dir>/*.json"),
    ("jq", "safe", "Convert <repo>.json records to TSV columns <field> and <column>", "jq -r '.[] | [.<field>, .<column>] | @tsv' <repo>.json"),
    ("jq", "safe", "Keep JSON objects from <repo>.json whose <column> field is present", "jq '[.[] | select(.<column> != null)]' <repo>.json"),
    ("jq", "safe", "Update nested JSON field metadata.<field> in <repo>.json to <tag>", "jq --arg value '<tag>' '.metadata.<field> = $value' <repo>.json"),
    ("jq", "safe", "Stream paths and scalar values from large JSON file <repo>.json", "jq --stream 'select(length == 2 and (.[1] | scalars))' <repo>.json"),
    ("yq", "safe", "Read YAML field spec.<field> from every document in <repo>.yaml", "yq eval-all '.spec.<field>' <repo>.yaml"),
    ("yq", "safe", "Set image tag <tag> in <repo>.yaml without editing the original", "yq '.spec.template.spec.containers[].image |= sub(\":.*$\", \":<tag>\")' <repo>.yaml"),
    ("yq", "safe", "Deep-merge <base>.yaml and <branch>.yaml with the branch file winning", "yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' <base>.yaml <branch>.yaml"),
    ("yq", "safe", "Select YAML documents labeled app <repo> from manifests.yaml", "yq 'select(.metadata.labels.app == \"<repo>\")' manifests.yaml"),
    ("yq", "caution", "Delete annotations named <field> in place from <repo>.yaml", "yq -i 'del(.metadata.annotations.<field>)' <repo>.yaml"),
    ("csv-tooling", "safe", "Select columns <field> and <column> from <repo>.csv with Miller", "mlr --csv cut -f <field>,<column> <repo>.csv"),
    ("csv-tooling", "safe", "Filter <repo>.csv to rows where <column> is nonempty using Miller", "mlr --csv filter '$<column> != \"\"' <repo>.csv"),
    ("csv-tooling", "safe", "Compute grouped statistics for <column> by <field> in <repo>.csv", "mlr --csv stats1 -a count,mean,p95 -f <column> -g <field> <repo>.csv"),
    ("csv-tooling", "safe", "Sort <repo>.csv numerically descending by <column> with csvkit", "csvsort -c <column> -r <repo>.csv"),
    ("csv-tooling", "safe", "Join <repo>.csv to <table>.csv on <field> using csvkit", "csvjoin -c <field> <repo>.csv <table>.csv"),
    ("csv-tooling", "safe", "Run a SQL aggregation over <repo>.csv from standard input using csvkit", "csvsql --query \"SELECT <field>, COUNT(*) AS n FROM stdin GROUP BY <field>\" < <repo>.csv"),
    ("parquet-tooling", "safe", "Show the schema of Parquet file <repo>.parquet", "parquet-tools schema <repo>.parquet"),
    ("parquet-tooling", "safe", "Display the first ten rows and selected columns from <repo>.parquet", "duckdb -c \"SELECT <field>, <column> FROM read_parquet('<repo>.parquet') LIMIT 10;\""),
    ("parquet-tooling", "safe", "Count rows by <field> directly from <repo>.parquet", "duckdb -c \"SELECT <field>, count(*) FROM read_parquet('<repo>.parquet') GROUP BY <field>;\""),
    ("parquet-tooling", "caution", "Convert <repo>.csv to compressed Parquet with DuckDB", "duckdb -c \"COPY (SELECT * FROM read_csv_auto('<repo>.csv')) TO '<repo>.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);\""),
    ("arrow-tooling", "safe", "Inspect the Arrow IPC schema in <repo>.arrow with Python", "python -c \"import pyarrow.ipc as i; f=i.open_file('<repo>.arrow'); print(f.schema)\""),
    ("arrow-tooling", "caution", "Convert <repo>.parquet to Arrow IPC format", "python -c \"import pyarrow.parquet as p, pyarrow.ipc as i; t=p.read_table('<repo>.parquet'); w=i.new_file('<repo>.arrow',t.schema); w.write_table(t); w.close()\""),

    # Media, documents, OCR and PDFs.
    ("ffmpeg", "safe", "Inspect streams and container metadata in <repo>.mp4 as JSON", "ffprobe -v error -show_format -show_streams -of json <repo>.mp4"),
    ("ffmpeg", "caution", "Transcode <repo>.mp4 to H.265 while copying its audio stream", "ffmpeg -i <repo>.mp4 -map 0:v:0 -map 0:a? -c:v libx265 -crf 28 -c:a copy <repo>-h265.mkv"),
    ("ffmpeg", "caution", "Extract one frame every ten seconds from <repo>.mp4", "ffmpeg -i <repo>.mp4 -vf 'fps=1/10' <repo>-frame-%05d.png"),
    ("ffmpeg", "caution", "Normalize <repo>.wav to broadcast loudness and save FLAC", "ffmpeg -i <repo>.wav -af loudnorm=I=-16:LRA=11:TP=-1.5 -c:a flac <repo>-normalized.flac"),
    ("ffmpeg", "caution", "Create an HLS VOD playlist from <repo>.mp4", "ffmpeg -i <repo>.mp4 -c:v libx264 -c:a aac -hls_time 6 -hls_playlist_type vod -hls_segment_filename '<repo>-%03d.ts' <repo>.m3u8"),
    ("imagemagick", "safe", "Report image dimensions and color space for <repo>.png", "identify -format '%f %wx%h %[colorspace]\\n' <repo>.png"),
    ("imagemagick", "caution", "Resize <repo>.png within 1600 by 1600 without enlarging it", "magick <repo>.png -resize '1600x1600>' -strip <repo>-web.png"),
    ("imagemagick", "caution", "Auto-orient and remove metadata from <repo>.jpg", "magick <repo>.jpg -auto-orient -strip <repo>-clean.jpg"),
    ("pandoc", "caution", "Convert <repo>.md to a standalone HTML5 document with a table of contents", "pandoc <repo>.md --standalone --toc --from=gfm --to=html5 -o <repo>.html"),
    ("pandoc", "caution", "Convert <repo>.docx to GitHub-flavored Markdown and extract media", "pandoc <repo>.docx --to=gfm --extract-media=<repo>-media -o <repo>.md"),
    ("ocr", "caution", "OCR scanned PDF <repo>.pdf, deskew it, and preserve searchable text", "ocrmypdf --deskew --rotate-pages --skip-text <repo>.pdf <repo>-ocr.pdf"),
    ("ocr", "safe", "Recognize English text in image <repo>.png and print it to standard output", "tesseract <repo>.png stdout -l eng --psm 6"),
    ("pdf-tooling", "safe", "Show PDF page count, encryption status, and metadata for <repo>.pdf", "pdfinfo <repo>.pdf"),
    ("pdf-tooling", "caution", "Extract pages 3 through 8 from <repo>.pdf into a new PDF", "qpdf <repo>.pdf --pages . 3-8 -- <repo>-pages-3-8.pdf"),
    ("pdf-tooling", "caution", "Linearize <repo>.pdf for fast web viewing", "qpdf --linearize <repo>.pdf <repo>-linearized.pdf"),

    # Compression, backup and cloud synchronization.
    ("compression", "caution", "Create a reproducible zstd-compressed tar archive of directory <dir>", "tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -C <repo> -cf - <dir> | zstd -19 -T0 -o <repo>-<tag>.tar.zst"),
    ("compression", "safe", "Test the integrity of zstd archive <repo>-<tag>.tar.zst", "zstd --test <repo>-<tag>.tar.zst"),
    ("compression", "safe", "List files in <repo>-<tag>.tar.zst without extracting them", "tar --use-compress-program=unzstd -tvf <repo>-<tag>.tar.zst"),
    ("compression", "caution", "Create a maximum-compression 7z archive of <dir> in <repo>", "7z a -t7z -mx=9 -mmt=on <repo>-<tag>.7z <repo>/<dir>"),
    ("compression", "safe", "Test all files in 7z archive <repo>-<tag>.7z", "7z t <repo>-<tag>.7z"),
    ("restic", "caution", "Back up <repo>/<dir> to the configured restic repository with tags", "restic backup <repo>/<dir> --tag <repo> --tag <tag>"),
    ("restic", "safe", "List restic snapshots tagged for <repo>", "restic snapshots --tag <repo> --json"),
    ("restic", "safe", "Check restic repository data using a five-percent read subset and a <repo> cache", "restic check --read-data-subset=5% --with-cache --cache-dir .restic-cache/<repo>"),
    ("restic", "destructive", "Forget old <repo> restic snapshots according to retention policy and prune", "restic forget --tag <repo> --keep-daily 7 --keep-weekly 5 --keep-monthly 12 --prune"),
    ("borg", "caution", "Create a compressed Borg archive of <repo>/<dir>", "borg create --stats --compression zstd,9 '<remote>::<repo>-<tag>' <repo>/<dir>"),
    ("borg", "safe", "Verify the Borg archive named <repo>-<tag>", "borg check --verify-data '<remote>::<repo>-<tag>'"),
    ("borg", "caution", "Extract only <dir> from Borg archive <repo>-<tag>", "borg extract --list '<remote>::<repo>-<tag>' <repo>/<dir>"),
    ("rclone", "safe", "Preview synchronization of <repo>/<dir> to <bucket> with checksums", "rclone sync <repo>/<dir> <bucket> --checksum --dry-run --progress"),
    ("rclone", "caution", "Copy new and changed files from <repo>/<dir> to <bucket>", "rclone copy <repo>/<dir> <bucket> --checksum --transfers 8 --checkers 16 --progress"),
    ("rclone", "safe", "Compare <repo>/<dir> against <bucket> by checksum without modifying either side", "rclone check <repo>/<dir> <bucket> --one-way --combined <repo>-rclone-check.txt"),

    # Checksums, signing, SBOMs and supply-chain/container inspection.
    ("checksums", "safe", "Create a SHA-256 checksum manifest for files under <repo>/<dir>", "find <repo>/<dir> -type f -print0 | sort -z | xargs -0 sha256sum > <repo>-SHA256SUMS"),
    ("checksums", "safe", "Verify every entry in checksum manifest <repo>-SHA256SUMS", "sha256sum --check --strict <repo>-SHA256SUMS"),
    ("signing", "caution", "Create an armored detached GPG signature for <repo>-<tag>.tar.zst", "gpg --armor --detach-sign <repo>-<tag>.tar.zst"),
    ("signing", "safe", "Verify the detached GPG signature of <repo>-<tag>.tar.zst", "gpg --verify <repo>-<tag>.tar.zst.asc <repo>-<tag>.tar.zst"),
    ("signing", "caution", "Sign container image <image> with Cosign using key <repo>.key", "cosign sign --key <repo>.key '<image>'"),
    ("signing", "safe", "Verify signatures on container image <image> with Cosign", "cosign verify --key <repo>.pub '<image>'"),
    ("sbom", "safe", "Generate a CycloneDX JSON SBOM for directory <repo>", "syft dir:<repo> -o cyclonedx-json=<repo>-sbom.cdx.json"),
    ("sbom", "safe", "Generate an SPDX JSON SBOM for container image <image>", "syft '<image>' -o spdx-json=<repo>-image.spdx.json"),
    ("vulnerability-scan", "safe", "Scan container image <image> for high and critical vulnerabilities", "trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 0 '<image>'"),
    ("vulnerability-scan", "safe", "Scan <repo> filesystem dependencies and secrets with Trivy", "trivy fs --scanners vuln,secret --severity HIGH,CRITICAL <repo>"),
    ("vulnerability-scan", "safe", "Scan the <repo> SBOM with Grype and fail at high severity", "grype sbom:<repo>-sbom.cdx.json --fail-on high"),
    ("container-inspection", "safe", "Inspect container image <image> configuration as JSON", "skopeo inspect --config 'docker://<image>' | jq ."),
    ("container-inspection", "caution", "Copy container image <image> into an OCI archive", "skopeo copy 'docker://<image>' 'oci-archive:<repo>-<tag>.tar:<tag>'"),
    ("container-inspection", "safe", "Show the layer history of container image <image> without truncation", "docker history --no-trunc '<image>'"),
    ("container-inspection", "safe", "Display the files added and removed by each layer of image <image>", "dive '<image>' --ci"),

    # Regex and advanced text-processing tools.
    ("ripgrep", "safe", "Search <repo> for regex <pattern> only in tracked source files", "cd <repo> && rg --line-number --hidden --glob '!.git' '<pattern>'"),
    ("ripgrep", "safe", "List files under <repo> containing pattern <pattern> exactly once", "rg --count-matches '<pattern>' <repo> | awk -F: '$NF == 1 {sub(/:[^:]+$/,\"\"); print}'"),
    ("ripgrep", "safe", "Search across newlines for <pattern> followed later by <field> in <repo>", "rg --multiline --multiline-dotall '<pattern>.*?<field>' <repo>"),
    ("pcre2", "safe", "Print only the captured identifier following <field> in <file>", "pcre2grep -o1 '<field>=([A-Za-z0-9_-]+)' <file>"),
    ("awk", "safe", "Compute the mean of the second numeric column per first-column key in <repo>.tsv", "awk -F '\\t' 'NR>1 {sum[$1]+=$2; n[$1]++} END {for (k in sum) print k, sum[k]/n[k]}' <repo>.tsv"),
    ("awk", "safe", "Print blocks in <repo>.log from lines matching <pattern> through lines matching <field>", "awk '/<pattern>/{show=1} show; /<field>/{show=0}' <repo>.log"),
    ("awk", "safe", "Join sorted <repo>.tsv and <table>.tsv on their first tab-separated column", "join -t $'\\t' -1 1 -2 1 <(sort -t $'\\t' -k1,1 <repo>.tsv) <(sort -t $'\\t' -k1,1 <table>.tsv)"),
    ("sed", "safe", "Print the first block between markers <pattern> and <field> in <repo>.log", "sed -n '/<pattern>/,/<field>/p' <repo>.log"),
    ("perl", "caution", "Replace multiline text between <pattern> and <field> in <file>, keeping the markers", "perl -0pi.bak -e 's/(<pattern>).*?(<field>)/$1\\nREDACTED\\n$2/sg' <file>"),
    ("text-encoding", "safe", "Convert <repo>.txt from Windows-1252 to UTF-8 and reject invalid input", "iconv -f WINDOWS-1252 -t UTF-8 <repo>.txt > <repo>-utf8.txt"),
    ("text-encoding", "safe", "Detect MIME type and character encoding of <file> in <repo>", "file --brief --mime <repo>/<file>"),
    ("text-diff", "safe", "Compare JSON files <repo>.json and <table>.json after canonical key sorting", "diff -u <(jq -S . <repo>.json) <(jq -S . <table>.json)"),
    ("text-diff", "safe", "Produce a word-level colored diff between <repo>.txt and <table>.txt", "git diff --no-index --word-diff=color <repo>.txt <table>.txt"),
    ("log-analysis", "safe", "Show the ten most frequent values of JSON log field <field> in <repo>.jsonl", "jq -r '.<field> // empty' <repo>.jsonl | sort | uniq -c | sort -nr | head -n 10"),
    ("log-analysis", "safe", "Count JSON log events by minute and <field> in <repo>.jsonl", "jq -r '[.timestamp[0:16], .<field>] | @tsv' <repo>.jsonl | sort | uniq -c"),
    ("log-analysis", "safe", "Extract records around matches for <pattern> in <repo>.log with context", "rg --line-number --before-context 2 --after-context 3 '<pattern>' <repo>.log"),
]


def render(template: str, context: dict[str, str]) -> str:
    result = template
    for key, value in context.items():
        result = result.replace(f"<{key}>", value)
    if "<" in result and ">" in result:
        unresolved = [part.split(">", 1)[0] for part in result.split("<")[1:] if ">" in part]
        raise ValueError(f"unresolved placeholders {unresolved!r} in {template!r}")
    return result


def build() -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    seen_nl: set[str] = set()
    seen_bash: set[str] = set()
    for spec_index, (category, risk, nl_template, bash_template) in enumerate(SPECS):
        family = f"{category}-{spec_index:03d}"
        for context in CONTEXTS:
            nl = " ".join(render(nl_template, context).split())
            bash = render(bash_template, context).strip()
            if not nl or not bash or "\n" in bash or "\r" in bash:
                raise ValueError(f"invalid record: {nl!r} -> {bash!r}")
            if risk not in {"safe", "caution", "destructive"}:
                raise ValueError(f"invalid risk {risk!r}")
            nl_key = nl.casefold()
            if nl_key in seen_nl:
                raise ValueError(f"duplicate natural language prompt: {nl}")
            if bash in seen_bash:
                raise ValueError(f"duplicate Bash command: {bash}")
            seen_nl.add(nl_key)
            seen_bash.add(bash)
            records.append(
                {
                    "nl": nl,
                    "bash": bash,
                    "category": category,
                    "family": family,
                    "risk": risk,
                    "source": "manual-curation",
                }
            )
    return records


def main() -> None:
    records = build()
    if len(records) < 3400:
        raise RuntimeError(f"expected at least 3,400 records, got {len(records):,}")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    categories = Counter(item["category"] for item in records)
    risks = Counter(item["risk"] for item in records)
    print(f"wrote {len(records):,} unique records to {OUTPUT}")
    print(f"categories ({len(categories)}): {dict(sorted(categories.items()))}")
    print(f"risks: {dict(sorted(risks.items()))}")


if __name__ == "__main__":
    main()
