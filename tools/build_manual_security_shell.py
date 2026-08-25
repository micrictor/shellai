"""Build a deterministic, manually curated NL-to-Bash security/shell shard.

The examples are authored as command-family records below.  Parameter expansion
only substitutes realistic concrete targets; it does not invent commands or
natural-language descriptions.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "manual_synth_security_shell.json"
ALLOWED_RISKS = {"safe", "caution", "destructive"}
examples: list[dict[str, str]] = []
family_counts: Counter[str] = Counter()


def add_family(
    category: str,
    risk: str,
    nl_templates: str | Sequence[str],
    bash_template: str,
    rows: Iterable[Mapping[str, object]],
) -> None:
    """Expand one manually authored operation across curated parameter rows."""
    if risk not in ALLOWED_RISKS:
        raise ValueError(f"invalid risk label: {risk}")
    family_counts[category] += 1
    family = f"{category}:{family_counts[category]:03d}"
    templates = (nl_templates,) if isinstance(nl_templates, str) else tuple(nl_templates)
    for index, row in enumerate(rows):
        values = {key: str(value) for key, value in row.items()}
        try:
            nl = templates[index % len(templates)].format(**values).strip()
            bash = bash_template.format(**values).strip()
        except (KeyError, ValueError) as exc:
            raise ValueError(f"bad template in {family}: {bash_template!r}") from exc
        examples.append(
            {
                "nl": nl,
                "bash": bash,
                "category": category,
                "risk": risk,
                "source": "manual-curation",
                "family": family,
            }
        )


def rows_with(rows: Sequence[Mapping[str, object]], **extra: object) -> list[dict[str, object]]:
    return [{**row, **extra} for row in rows]


CERTS = [
    {"name": "api", "cert": "certs/api.crt", "key": "private/api.key", "csr": "requests/api.csr", "cn": "api.example.test", "host": "api.example.test", "port": 443, "ca": "ca/internal-ca.pem", "p12": "bundles/api.p12"},
    {"name": "web", "cert": "certs/web.pem", "key": "private/web.key", "csr": "requests/web.csr", "cn": "www.example.test", "host": "www.example.test", "port": 443, "ca": "ca/root-ca.pem", "p12": "bundles/web.p12"},
    {"name": "mail", "cert": "certs/mail.crt", "key": "private/mail.key", "csr": "requests/mail.csr", "cn": "mail.example.test", "host": "mail.example.test", "port": 465, "ca": "ca/org-chain.pem", "p12": "bundles/mail.pfx"},
    {"name": "ldap", "cert": "certs/ldap.pem", "key": "private/ldap.key", "csr": "requests/ldap.csr", "cn": "ldap.example.test", "host": "ldap.example.test", "port": 636, "ca": "ca/directory-ca.pem", "p12": "bundles/ldap.p12"},
    {"name": "git", "cert": "certs/git.crt", "key": "private/git.key", "csr": "requests/git.csr", "cn": "git.example.test", "host": "git.example.test", "port": 443, "ca": "ca/dev-ca.pem", "p12": "bundles/git.p12"},
    {"name": "vpn", "cert": "certs/vpn.pem", "key": "private/vpn.key", "csr": "requests/vpn.csr", "cn": "vpn.example.test", "host": "vpn.example.test", "port": 443, "ca": "ca/vpn-ca.pem", "p12": "bundles/vpn.p12"},
    {"name": "metrics", "cert": "certs/metrics.crt", "key": "private/metrics.key", "csr": "requests/metrics.csr", "cn": "metrics.example.test", "host": "metrics.example.test", "port": 8443, "ca": "ca/observability-ca.pem", "p12": "bundles/metrics.p12"},
    {"name": "registry", "cert": "certs/registry.pem", "key": "private/registry.key", "csr": "requests/registry.csr", "cn": "registry.example.test", "host": "registry.example.test", "port": 5000, "ca": "ca/registry-ca.pem", "p12": "bundles/registry.p12"},
    {"name": "db", "cert": "certs/db.crt", "key": "private/db.key", "csr": "requests/db.csr", "cn": "db.example.test", "host": "db.example.test", "port": 5432, "ca": "ca/database-ca.pem", "p12": "bundles/db.p12"},
    {"name": "broker", "cert": "certs/broker.pem", "key": "private/broker.key", "csr": "requests/broker.csr", "cn": "broker.example.test", "host": "broker.example.test", "port": 8883, "ca": "ca/messaging-ca.pem", "p12": "bundles/broker.p12"},
    {"name": "admin", "cert": "certs/admin.crt", "key": "private/admin.key", "csr": "requests/admin.csr", "cn": "admin.example.test", "host": "admin.example.test", "port": 9443, "ca": "ca/admin-ca.pem", "p12": "bundles/admin.p12"},
    {"name": "proxy", "cert": "certs/proxy.pem", "key": "private/proxy.key", "csr": "requests/proxy.csr", "cn": "proxy.example.test", "host": "proxy.example.test", "port": 10443, "ca": "ca/edge-ca.pem", "p12": "bundles/proxy.p12"},
]

FILES = [
    {"file": "artifacts/release.tar.gz", "sig": "artifacts/release.tar.gz.sig", "out": "artifacts/release.tar.gz.enc", "label": "release archive"},
    {"file": "backups/config-backup.tgz", "sig": "backups/config-backup.tgz.sig", "out": "backups/config-backup.tgz.enc", "label": "configuration backup"},
    {"file": "images/disk.raw", "sig": "images/disk.raw.sig", "out": "images/disk.raw.enc", "label": "disk image"},
    {"file": "reports/audit.json", "sig": "reports/audit.json.sig", "out": "reports/audit.json.enc", "label": "audit report"},
    {"file": "packages/agent.deb", "sig": "packages/agent.deb.sig", "out": "packages/agent.deb.enc", "label": "Debian package"},
    {"file": "packages/agent.rpm", "sig": "packages/agent.rpm.sig", "out": "packages/agent.rpm.enc", "label": "RPM package"},
    {"file": "exports/customers.csv", "sig": "exports/customers.csv.sig", "out": "exports/customers.csv.enc", "label": "customer export"},
    {"file": "manifests/prod.yaml", "sig": "manifests/prod.yaml.sig", "out": "manifests/prod.yaml.enc", "label": "production manifest"},
    {"file": "logs/security.log", "sig": "logs/security.log.sig", "out": "logs/security.log.enc", "label": "security log"},
    {"file": "firmware/router.bin", "sig": "firmware/router.bin.sig", "out": "firmware/router.bin.enc", "label": "router firmware"},
    {"file": "keys/public-key.txt", "sig": "keys/public-key.txt.sig", "out": "keys/public-key.txt.enc", "label": "public-key record"},
    {"file": "snapshots/database.dump", "sig": "snapshots/database.dump.sig", "out": "snapshots/database.dump.enc", "label": "database snapshot"},
]

SSH = [
    {"host": "bastion.example.test", "user": "ops", "port": 22, "key": "~/.ssh/id_bastion", "local": 15432, "remote_host": "db.internal.test", "remote": 5432, "jump": "gateway.example.test"},
    {"host": "git.example.test", "user": "git", "port": 2222, "key": "~/.ssh/id_git", "local": 18080, "remote_host": "web.internal.test", "remote": 8080, "jump": "bastion.example.test"},
    {"host": "admin.example.test", "user": "admin", "port": 22, "key": "~/.ssh/id_admin", "local": 16379, "remote_host": "cache.internal.test", "remote": 6379, "jump": "gateway.example.test"},
    {"host": "backup.example.test", "user": "backup", "port": 2201, "key": "~/.ssh/id_backup", "local": 13306, "remote_host": "mysql.internal.test", "remote": 3306, "jump": "bastion.example.test"},
    {"host": "metrics.example.test", "user": "monitor", "port": 22, "key": "~/.ssh/id_metrics", "local": 19090, "remote_host": "prometheus.internal.test", "remote": 9090, "jump": "ops-gateway.example.test"},
    {"host": "registry.example.test", "user": "deploy", "port": 2022, "key": "~/.ssh/id_registry", "local": 15000, "remote_host": "registry.internal.test", "remote": 5000, "jump": "bastion.example.test"},
    {"host": "logs.example.test", "user": "analyst", "port": 22, "key": "~/.ssh/id_logs", "local": 19200, "remote_host": "search.internal.test", "remote": 9200, "jump": "audit-gateway.example.test"},
    {"host": "build.example.test", "user": "builder", "port": 2220, "key": "~/.ssh/id_build", "local": 18081, "remote_host": "ci.internal.test", "remote": 8081, "jump": "dev-gateway.example.test"},
    {"host": "vpn.example.test", "user": "netops", "port": 22, "key": "~/.ssh/id_vpn", "local": 18443, "remote_host": "console.internal.test", "remote": 8443, "jump": "edge.example.test"},
    {"host": "mail.example.test", "user": "mailops", "port": 2223, "key": "~/.ssh/id_mail", "local": 19933, "remote_host": "imap.internal.test", "remote": 993, "jump": "bastion.example.test"},
    {"host": "dns.example.test", "user": "dnsops", "port": 22, "key": "~/.ssh/id_dns", "local": 18053, "remote_host": "resolver.internal.test", "remote": 8053, "jump": "net-gateway.example.test"},
    {"host": "staging.example.test", "user": "release", "port": 2024, "key": "~/.ssh/id_staging", "local": 13000, "remote_host": "app.internal.test", "remote": 3000, "jump": "dev-gateway.example.test"},
]

HTTP = [
    {"url": "https://api.example.test/v1/health", "host": "api.example.test", "ip": "192.0.2.10", "file": "payloads/health.json", "out": "responses/health.json", "token": "$API_TOKEN"},
    {"url": "https://api.example.test/v1/users/42", "host": "api.example.test", "ip": "192.0.2.11", "file": "payloads/user.json", "out": "responses/user.json", "token": "$API_TOKEN"},
    {"url": "https://registry.example.test/v2/catalog", "host": "registry.example.test", "ip": "192.0.2.12", "file": "payloads/catalog.json", "out": "responses/catalog.json", "token": "$REGISTRY_TOKEN"},
    {"url": "https://metrics.example.test/api/query", "host": "metrics.example.test", "ip": "192.0.2.13", "file": "payloads/query.json", "out": "responses/metrics.json", "token": "$METRICS_TOKEN"},
    {"url": "https://git.example.test/api/projects/7", "host": "git.example.test", "ip": "192.0.2.14", "file": "payloads/project.json", "out": "responses/project.json", "token": "$GIT_TOKEN"},
    {"url": "https://status.example.test/incidents", "host": "status.example.test", "ip": "192.0.2.15", "file": "payloads/incident.json", "out": "responses/incidents.json", "token": "$STATUS_TOKEN"},
    {"url": "https://web.example.test/assets/app.js", "host": "web.example.test", "ip": "192.0.2.16", "file": "assets/app.js", "out": "downloads/app.js", "token": "$WEB_TOKEN"},
    {"url": "https://backup.example.test/snapshots/latest", "host": "backup.example.test", "ip": "192.0.2.17", "file": "snapshots/latest.tgz", "out": "downloads/latest.tgz", "token": "$BACKUP_TOKEN"},
    {"url": "https://admin.example.test/api/config", "host": "admin.example.test", "ip": "192.0.2.18", "file": "payloads/config.json", "out": "responses/config.json", "token": "$ADMIN_TOKEN"},
    {"url": "https://hooks.example.test/deploy", "host": "hooks.example.test", "ip": "192.0.2.19", "file": "payloads/deploy.json", "out": "responses/deploy.json", "token": "$HOOK_TOKEN"},
    {"url": "https://mail.example.test/api/queue", "host": "mail.example.test", "ip": "192.0.2.20", "file": "payloads/message.json", "out": "responses/queue.json", "token": "$MAIL_TOKEN"},
    {"url": "https://docs.example.test/search?q=shell", "host": "docs.example.test", "ip": "192.0.2.21", "file": "payloads/search.json", "out": "responses/search.json", "token": "$DOCS_TOKEN"},
]

DOMAINS = [
    {"domain": "api.example.test", "type": "A", "server": "192.0.2.53", "addr": "192.0.2.10"},
    {"domain": "www.example.test", "type": "AAAA", "server": "198.51.100.53", "addr": "192.0.2.20"},
    {"domain": "example.test", "type": "MX", "server": "203.0.113.53", "addr": "192.0.2.30"},
    {"domain": "_dmarc.example.test", "type": "TXT", "server": "192.0.2.53", "addr": "192.0.2.40"},
    {"domain": "example.test", "type": "NS", "server": "198.51.100.53", "addr": "192.0.2.50"},
    {"domain": "_sip._tcp.example.test", "type": "SRV", "server": "203.0.113.53", "addr": "192.0.2.60"},
    {"domain": "ca.example.test", "type": "CAA", "server": "192.0.2.53", "addr": "192.0.2.70"},
    {"domain": "vpn.example.test", "type": "A", "server": "198.51.100.53", "addr": "192.0.2.80"},
    {"domain": "mail.example.test", "type": "AAAA", "server": "203.0.113.53", "addr": "192.0.2.90"},
    {"domain": "registry.example.test", "type": "A", "server": "192.0.2.53", "addr": "192.0.2.100"},
    {"domain": "metrics.example.test", "type": "TXT", "server": "198.51.100.53", "addr": "192.0.2.110"},
    {"domain": "git.example.test", "type": "SSHFP", "server": "203.0.113.53", "addr": "192.0.2.120"},
]

NETS = [
    {"iface": "eth0", "host": "192.0.2.10", "port": 443, "net": "192.0.2.0/24", "pcap": "captures/web.pcap", "service": "https"},
    {"iface": "ens3", "host": "198.51.100.20", "port": 22, "net": "198.51.100.0/24", "pcap": "captures/ssh.pcap", "service": "ssh"},
    {"iface": "enp5s0", "host": "203.0.113.30", "port": 53, "net": "203.0.113.0/24", "pcap": "captures/dns.pcap", "service": "domain"},
    {"iface": "wlan0", "host": "192.0.2.40", "port": 8080, "net": "192.0.2.32/28", "pcap": "captures/proxy.pcap", "service": "http-alt"},
    {"iface": "bond0", "host": "198.51.100.50", "port": 5432, "net": "198.51.100.48/28", "pcap": "captures/postgres.pcap", "service": "postgresql"},
    {"iface": "br0", "host": "203.0.113.60", "port": 6379, "net": "203.0.113.56/29", "pcap": "captures/redis.pcap", "service": "redis"},
    {"iface": "wg0", "host": "192.0.2.70", "port": 51820, "net": "192.0.2.64/27", "pcap": "captures/wireguard.pcap", "service": "wireguard"},
    {"iface": "tun0", "host": "198.51.100.80", "port": 8443, "net": "198.51.100.64/27", "pcap": "captures/vpn.pcap", "service": "https-alt"},
    {"iface": "eno1", "host": "203.0.113.90", "port": 25, "net": "203.0.113.88/29", "pcap": "captures/smtp.pcap", "service": "smtp"},
    {"iface": "enp2s0", "host": "192.0.2.100", "port": 9100, "net": "192.0.2.96/28", "pcap": "captures/metrics.pcap", "service": "jetdirect"},
    {"iface": "docker0", "host": "198.51.100.110", "port": 5000, "net": "198.51.100.96/28", "pcap": "captures/registry.pcap", "service": "commplex-main"},
    {"iface": "veth0", "host": "203.0.113.120", "port": 9090, "net": "203.0.113.112/28", "pcap": "captures/prometheus.pcap", "service": "websm"},
]

PATHS = [
    {"path": "/srv/app", "file": "/srv/app/config.yaml", "user": "app", "group": "app", "event": "close_write"},
    {"path": "/etc/nginx", "file": "/etc/nginx/nginx.conf", "user": "www-data", "group": "www-data", "event": "modify"},
    {"path": "/var/log/app", "file": "/var/log/app/service.log", "user": "logreader", "group": "adm", "event": "create"},
    {"path": "/opt/releases", "file": "/opt/releases/current.json", "user": "deploy", "group": "release", "event": "moved_to"},
    {"path": "/var/backups", "file": "/var/backups/config.tgz", "user": "backup", "group": "backup", "event": "close_write"},
    {"path": "/srv/uploads", "file": "/srv/uploads/incoming.dat", "user": "uploader", "group": "uploads", "event": "create"},
    {"path": "/etc/ssh", "file": "/etc/ssh/sshd_config", "user": "auditor", "group": "security", "event": "modify"},
    {"path": "/var/lib/registry", "file": "/var/lib/registry/state.db", "user": "registry", "group": "registry", "event": "close_write"},
    {"path": "/srv/reports", "file": "/srv/reports/daily.csv", "user": "analyst", "group": "analytics", "event": "moved_to"},
    {"path": "/opt/agent", "file": "/opt/agent/agent.conf", "user": "agent", "group": "ops", "event": "attrib"},
    {"path": "/var/spool/mail", "file": "/var/spool/mail/alerts", "user": "postfix", "group": "mail", "event": "create"},
    {"path": "/srv/static", "file": "/srv/static/index.html", "user": "web", "group": "web", "event": "delete"},
]

PROCS = [
    {"pid": 101, "proc": "sshd", "user": "root", "signal": "HUP", "limit": 4096},
    {"pid": 242, "proc": "nginx", "user": "www-data", "signal": "USR1", "limit": 8192},
    {"pid": 383, "proc": "postgres", "user": "postgres", "signal": "TERM", "limit": 16384},
    {"pid": 424, "proc": "redis-server", "user": "redis", "signal": "USR2", "limit": 32768},
    {"pid": 565, "proc": "prometheus", "user": "prometheus", "signal": "HUP", "limit": 65536},
    {"pid": 606, "proc": "vector", "user": "vector", "signal": "TERM", "limit": 12288},
    {"pid": 747, "proc": "containerd", "user": "root", "signal": "USR1", "limit": 2048},
    {"pid": 888, "proc": "named", "user": "bind", "signal": "HUP", "limit": 24576},
    {"pid": 929, "proc": "postfix", "user": "postfix", "signal": "TERM", "limit": 10240},
    {"pid": 1060, "proc": "chronyd", "user": "chrony", "signal": "HUP", "limit": 3072},
    {"pid": 1111, "proc": "auditd", "user": "root", "signal": "USR1", "limit": 5120},
    {"pid": 1252, "proc": "worker", "user": "app", "signal": "TERM", "limit": 20000},
]

# Four additional manually selected contexts keep every broad command family
# represented beyond the common web/database examples above.
CERTS.extend([
    {"name": "search", "cert": "certs/search.crt", "key": "private/search.key", "csr": "requests/search.csr", "cn": "search.example.test", "host": "search.example.test", "port": 9243, "ca": "ca/search-ca.pem", "p12": "bundles/search.p12"},
    {"name": "auth", "cert": "certs/auth.pem", "key": "private/auth.key", "csr": "requests/auth.csr", "cn": "auth.example.test", "host": "auth.example.test", "port": 443, "ca": "ca/identity-ca.pem", "p12": "bundles/auth.p12"},
    {"name": "queue", "cert": "certs/queue.crt", "key": "private/queue.key", "csr": "requests/queue.csr", "cn": "queue.example.test", "host": "queue.example.test", "port": 5671, "ca": "ca/queue-ca.pem", "p12": "bundles/queue.p12"},
    {"name": "files", "cert": "certs/files.pem", "key": "private/files.key", "csr": "requests/files.csr", "cn": "files.example.test", "host": "files.example.test", "port": 443, "ca": "ca/storage-ca.pem", "p12": "bundles/files.p12"},
])
FILES.extend([
    {"file": "policies/access.rego", "sig": "policies/access.rego.sig", "out": "policies/access.rego.enc", "label": "access policy"},
    {"file": "inventory/hosts.json", "sig": "inventory/hosts.json.sig", "out": "inventory/hosts.json.enc", "label": "host inventory"},
    {"file": "certs/trust-bundle.pem", "sig": "certs/trust-bundle.pem.sig", "out": "certs/trust-bundle.pem.enc", "label": "trust bundle"},
    {"file": "traces/startup.trace", "sig": "traces/startup.trace.sig", "out": "traces/startup.trace.enc", "label": "startup trace"},
])
SSH.extend([
    {"host": "search.example.test", "user": "searchops", "port": 2225, "key": "~/.ssh/id_search", "local": 19201, "remote_host": "search2.internal.test", "remote": 9201, "jump": "audit-gateway.example.test"},
    {"host": "auth.example.test", "user": "iam", "port": 22, "key": "~/.ssh/id_auth", "local": 18444, "remote_host": "idp.internal.test", "remote": 8444, "jump": "security-gateway.example.test"},
    {"host": "queue.example.test", "user": "mqops", "port": 2202, "key": "~/.ssh/id_queue", "local": 15672, "remote_host": "rabbit.internal.test", "remote": 5672, "jump": "bastion.example.test"},
    {"host": "files.example.test", "user": "storage", "port": 2026, "key": "~/.ssh/id_files", "local": 1445, "remote_host": "smb.internal.test", "remote": 445, "jump": "storage-gateway.example.test"},
])
HTTP.extend([
    {"url": "https://search.example.test/api/indexes", "host": "search.example.test", "ip": "192.0.2.22", "file": "payloads/index.json", "out": "responses/indexes.json", "token": "$SEARCH_TOKEN"},
    {"url": "https://auth.example.test/oauth/metadata", "host": "auth.example.test", "ip": "192.0.2.23", "file": "payloads/client.json", "out": "responses/oauth.json", "token": "$AUTH_TOKEN"},
    {"url": "https://queue.example.test/api/queues", "host": "queue.example.test", "ip": "192.0.2.24", "file": "payloads/queue.json", "out": "responses/queues.json", "token": "$QUEUE_TOKEN"},
    {"url": "https://files.example.test/api/shares", "host": "files.example.test", "ip": "192.0.2.25", "file": "payloads/share.json", "out": "responses/shares.json", "token": "$FILES_TOKEN"},
])
DOMAINS.extend([
    {"domain": "search.example.test", "type": "HTTPS", "server": "192.0.2.54", "addr": "192.0.2.130"},
    {"domain": "auth.example.test", "type": "TLSA", "server": "198.51.100.54", "addr": "192.0.2.140"},
    {"domain": "queue.example.test", "type": "SVCB", "server": "203.0.113.54", "addr": "192.0.2.150"},
    {"domain": "files.example.test", "type": "A", "server": "192.0.2.55", "addr": "192.0.2.160"},
])
NETS.extend([
    {"iface": "enp7s0", "host": "192.0.2.130", "port": 9243, "net": "192.0.2.128/28", "pcap": "captures/search.pcap", "service": "search"},
    {"iface": "enp8s0", "host": "198.51.100.140", "port": 8444, "net": "198.51.100.128/28", "pcap": "captures/auth.pcap", "service": "auth"},
    {"iface": "enp9s0", "host": "203.0.113.150", "port": 5672, "net": "203.0.113.144/28", "pcap": "captures/queue.pcap", "service": "amqp"},
    {"iface": "enp10s0", "host": "192.0.2.160", "port": 445, "net": "192.0.2.160/28", "pcap": "captures/files.pcap", "service": "microsoft-ds"},
])
PATHS.extend([
    {"path": "/srv/search", "file": "/srv/search/index.json", "user": "search", "group": "search", "event": "close_write"},
    {"path": "/etc/auth", "file": "/etc/auth/providers.yaml", "user": "iam", "group": "security", "event": "modify"},
    {"path": "/var/lib/queue", "file": "/var/lib/queue/definitions.json", "user": "rabbitmq", "group": "rabbitmq", "event": "moved_to"},
    {"path": "/srv/shares", "file": "/srv/shares/permissions.csv", "user": "storage", "group": "storage", "event": "attrib"},
])
PROCS.extend([
    {"pid": 1393, "proc": "opensearch", "user": "search", "signal": "TERM", "limit": 24000},
    {"pid": 1434, "proc": "keycloak", "user": "iam", "signal": "HUP", "limit": 12000},
    {"pid": 1575, "proc": "beam.smp", "user": "rabbitmq", "signal": "TERM", "limit": 28000},
    {"pid": 1616, "proc": "smbd", "user": "storage", "signal": "HUP", "limit": 16000},
])


def add_crypto() -> None:
    for nl, cmd in [
        (("Show the subject of {cert}", "Print only the certificate subject from {cert}"), "openssl x509 -in {cert} -noout -subject"),
        (("Show the issuer of {cert}", "Print only the issuer recorded in {cert}"), "openssl x509 -in {cert} -noout -issuer"),
        (("Show the validity dates of {cert}", "Print when {cert} starts and stops being valid"), "openssl x509 -in {cert} -noout -dates"),
        (("Print the SHA-256 fingerprint of {cert}", "Compute the SHA-256 certificate fingerprint for {cert}"), "openssl x509 -in {cert} -noout -fingerprint -sha256"),
        (("Display the subject alternative names in {cert}", "Show the SAN extension from {cert}"), "openssl x509 -in {cert} -noout -ext subjectAltName"),
        (("Verify {cert} against CA file {ca}", "Check the certificate chain for {cert} using {ca}"), "openssl verify -CAfile {ca} {cert}"),
        (("Check the structure and consistency of private key {key}", "Validate private key {key} without printing it"), "openssl pkey -in {key} -check -noout"),
        (("Print the public key derived from {key}", "Extract the public key from private key {key}"), "openssl pkey -in {key} -pubout"),
        (("Create a CSR for {cn} with key {key} and save it to {csr}", "Generate {csr} for common name {cn} using {key}"), "openssl req -new -key {key} -out {csr} -subj '/CN={cn}'"),
        (("Inspect CSR {csr} without printing its PEM body", "Display the decoded request details for {csr}"), "openssl req -in {csr} -noout -text"),
        (("Connect to {host}:{port} with SNI and show the certificate chain", "Inspect the TLS certificate chain served by {host} on port {port}"), "openssl s_client -connect {host}:{port} -servername {host} -showcerts </dev/null"),
        (("Test an explicit TLS 1.2 connection to {host}:{port}", "Connect to {host}:{port} using TLS 1.2 only"), "openssl s_client -connect {host}:{port} -servername {host} -tls1_2 </dev/null"),
        (("Extract certificates from {p12} without private keys", "Write only the certificates contained in {p12} to standard output"), "openssl pkcs12 -in {p12} -clcerts -nokeys"),
        (("Extract the unencrypted private key from {p12}", "Output the private key in {p12} without encrypting the exported key"), "openssl pkcs12 -in {p12} -nocerts -nodes"),
    ]:
        add_family("openssl-certificates", "caution" if "nodes" in cmd else "safe", nl, cmd, CERTS)

    for nl, cmd in [
        (("Compute the SHA-256 digest of the {label}", "Hash {file} with SHA-256"), "openssl dgst -sha256 {file}"),
        (("Sign the {label} with {key} and write {sig}", "Create a SHA-256 signature {sig} for {file} using {key}"), "openssl dgst -sha256 -sign {key} -out {sig} {file}"),
        (("Verify signature {sig} for the {label} with the public key in keys/release.pub", "Check {sig} against {file} using keys/release.pub"), "openssl dgst -sha256 -verify keys/release.pub -signature {sig} {file}"),
        (("Encrypt the {label} with AES-256-CBC, PBKDF2, and a salt", "Password-encrypt {file} as {out} using AES-256-CBC and PBKDF2"), "openssl enc -aes-256-cbc -salt -pbkdf2 -in {file} -out {out}"),
        (("Decrypt encrypted {out} to recovered/{file}", "Use AES-256-CBC with PBKDF2 to decrypt {out}"), "openssl enc -d -aes-256-cbc -pbkdf2 -in {out} -out recovered/{file}"),
        (("Base64-encode {file} without line wrapping", "Encode the {label} as a single Base64 line"), "openssl base64 -A -in {file}"),
    ]:
        add_family("openssl-data", "caution" if any(word in nl[0].lower() for word in ("encrypt", "decrypt", "sign")) else "safe", nl, cmd, [dict(x, key="private/release-signing.key") for x in FILES])

    identities = [
        {**row, "recipient": recipient, "identity": identity}
        for row, recipient, identity in zip(
            FILES,
            ["alice@example.test", "bob@example.test", "ops@example.test", "security@example.test", "release@example.test", "backup@example.test", "finance@example.test", "deploy@example.test", "audit@example.test", "firmware@example.test", "keys@example.test", "dba@example.test"],
            ["keys/alice.agekey", "keys/bob.agekey", "keys/ops.agekey", "keys/security.agekey", "keys/release.agekey", "keys/backup.agekey", "keys/finance.agekey", "keys/deploy.agekey", "keys/audit.agekey", "keys/firmware.agekey", "keys/keys.agekey", "keys/dba.agekey"],
        )
    ]
    for nl, cmd, risk in [
        (("Encrypt the {label} for GPG recipient {recipient} and save {out}.gpg", "Create armored GPG file {out}.gpg from {file} for {recipient}"), "gpg --armor --output {out}.gpg --encrypt --recipient {recipient} {file}", "caution"),
        (("Create detached GPG signature {sig} for the {label}", "Sign {file} with a detached signature at {sig}"), "gpg --detach-sign --output {sig} {file}", "caution"),
        (("Verify detached GPG signature {sig} for the {label}", "Check GPG signature {sig} against {file}"), "gpg --verify {sig} {file}", "safe"),
        (("Decrypt {out}.gpg with GPG to recovered/{file}", "Use GPG to recover {out}.gpg into recovered/{file}"), "gpg --output recovered/{file} --decrypt {out}.gpg", "caution"),
        (("Show GPG keys matching {recipient}", "List public GPG keys for {recipient}"), "gpg --list-keys --with-fingerprint {recipient}", "safe"),
        (("Export the public GPG key for {recipient} in ASCII armor", "Print an armored public key export for {recipient}"), "gpg --armor --export {recipient}", "safe"),
        (("Encrypt the {label} with age recipients from {identity}.pub", "Use the age recipient file {identity}.pub to encrypt {file}"), "age --recipients-file {identity}.pub --output {out}.age {file}", "caution"),
        (("Decrypt age file {out}.age using {identity}", "Recover {out}.age with age identity file {identity}"), "age --decrypt --identity {identity} --output recovered/{file} {out}.age", "caution"),
        (("Encrypt the {label} using recipients listed in recipients/{recipient}.txt", "Use the age recipient file for {recipient} to encrypt {file}"), "age --recipients-file recipients/{recipient}.txt --output {out}.recipients.age {file}", "caution"),
        (("Inspect the packets in GPG file {sig}", "List the OpenPGP packet structure of {sig}"), "gpg --list-packets {sig}", "safe"),
    ]:
        add_family("gpg-age", risk, nl, cmd, identities)


def add_ssh_http_dns() -> None:
    for nl, cmd, risk in [
        (("Generate an Ed25519 SSH key at {key} for {user}@{host}", "Create a password-protected Ed25519 key {key} labeled {user}@{host}"), "ssh-keygen -t ed25519 -a 100 -f {key} -C '{user}@{host}'", "caution"),
        (("Show the SHA-256 fingerprint of SSH public key {key}.pub", "Print the fingerprint for {key}.pub"), "ssh-keygen -lf {key}.pub -E sha256", "safe"),
        (("Derive the public SSH key from private key {key}", "Print the public key corresponding to {key}"), "ssh-keygen -y -f {key}", "caution"),
        (("Scan the Ed25519 host key for {host} on port {port}", "Fetch {host}'s Ed25519 SSH host key from port {port}"), "ssh-keyscan -p {port} -t ed25519 {host}", "safe"),
        (("Search known_hosts for {host}", "Find entries for {host} in the SSH known-hosts file"), "ssh-keygen -F {host}", "safe"),
        (("Remove stale known_hosts entries for {host}", "Delete {host} from the SSH known-hosts file"), "ssh-keygen -R {host}", "destructive"),
        (("Show the fully resolved SSH configuration for {user}@{host}", "Print effective SSH options for user {user} connecting to {host}"), "ssh -G -p {port} -i {key} {user}@{host}", "safe"),
        (("Open local port {local} to {remote_host}:{remote} through {host}", "Create an SSH local tunnel from localhost:{local} to {remote_host}:{remote} via {host}"), "ssh -N -T -o ExitOnForwardFailure=yes -L {local}:{remote_host}:{remote} -p {port} -i {key} {user}@{host}", "caution"),
        (("Open SOCKS5 proxy localhost:{local} through {host}", "Create a dynamic SSH tunnel on local port {local} via {user}@{host}"), "ssh -N -T -o ExitOnForwardFailure=yes -D 127.0.0.1:{local} -p {port} -i {key} {user}@{host}", "caution"),
        (("Expose local port {remote} as remote localhost:{local} on {host}", "Create a reverse SSH tunnel from {host}:{local} to local port {remote}"), "ssh -N -T -o ExitOnForwardFailure=yes -R 127.0.0.1:{local}:127.0.0.1:{remote} -p {port} -i {key} {user}@{host}", "caution"),
        (("Connect to {host} through jump host {jump}", "SSH to {user}@{host} using {jump} as the proxy jump"), "ssh -J {jump} -p {port} -i {key} {user}@{host}", "safe"),
        (("Test SSH authentication to {host} without opening an interactive shell", "Run a batch-mode no-op over SSH to {user}@{host}"), "ssh -T -o BatchMode=yes -o ConnectTimeout=10 -p {port} -i {key} {user}@{host} true", "safe"),
        (("Add private key {key} to ssh-agent for one hour", "Load {key} into the SSH agent with a 3600-second lifetime"), "ssh-add -t 3600 {key}", "caution"),
        (("Copy config/hosts.txt to {host} while preserving timestamps", "Secure-copy config/hosts.txt to {user}@{host} on port {port}"), "scp -p -P {port} -i {key} config/hosts.txt {user}@{host}:~/hosts.txt", "caution"),
        (("Synchronize deploy/ to {host} over SSH without deleting remote files", "Use rsync over SSH to update /srv/deploy/ on {host}"), "rsync -a --partial -e 'ssh -p {port} -i {key}' deploy/ {user}@{host}:/srv/deploy/", "caution"),
    ]:
        add_family("ssh-advanced", risk, nl, cmd, SSH)

    for nl, cmd, risk in [
        (("Fetch {url} and fail on HTTP errors", "GET {url} silently while showing errors and failing for non-2xx responses"), "curl --fail --silent --show-error '{url}'", "safe"),
        (("Request only the response headers from {url}", "Send an HTTP HEAD request to {url}"), "curl --fail --head '{url}'", "safe"),
        (("Download {url} to {out} with three retries", "Save {url} as {out}, retrying transient failures three times"), "curl --fail --location --retry 3 --retry-all-errors --output {out} '{url}'", "safe"),
        (("Print only the HTTP status code returned by {url}", "Check {url} and output its numeric HTTP status"), "curl --silent --output /dev/null --write-out '%{{http_code}}\\n' '{url}'", "safe"),
        (("Fetch {url} using bearer token {token}", "Send an authenticated GET request to {url} with {token}"), "curl --fail --header \"Authorization: Bearer {token}\" '{url}'", "caution"),
        (("POST JSON file {file} to {url}", "Send {file} as an application/json POST body to {url}"), "curl --fail --request POST --header 'Content-Type: application/json' --data-binary '@{file}' '{url}'", "caution"),
        (("PUT JSON file {file} to {url}", "Replace the resource at {url} with JSON from {file}"), "curl --fail --request PUT --header 'Content-Type: application/json' --data-binary '@{file}' '{url}'", "caution"),
        (("PATCH {url} with JSON from {file}", "Apply the JSON patch in {file} to {url}"), "curl --fail --request PATCH --header 'Content-Type: application/json' --data-binary '@{file}' '{url}'", "caution"),
        (("Send an HTTP DELETE request to {url} with bearer authentication", "Delete {url} using token {token}"), "curl --fail --request DELETE --header \"Authorization: Bearer {token}\" '{url}'", "destructive"),
        (("Upload {file} to {url} as a multipart field named upload", "POST {file} to {url} using multipart form data"), "curl --fail --form 'upload=@{file}' '{url}'", "caution"),
        (("Resume downloading {url} into {out}", "Continue a partial download of {url} at {out}"), "curl --fail --location --continue-at - --output {out} '{url}'", "safe"),
        (("Download only the first 1024 bytes of {url}", "Request byte range 0 through 1023 from {url}"), "curl --fail --range 0-1023 '{url}'", "safe"),
        (("Fetch {url} with a 5-second connection timeout and 30-second total timeout", "Limit the connection and total duration when requesting {url}"), "curl --fail --connect-timeout 5 --max-time 30 '{url}'", "safe"),
        (("Resolve {host} to {ip} locally when fetching {url}", "Request {url} while overriding DNS for {host} with {ip}"), "curl --fail --resolve '{host}:443:{ip}' '{url}'", "safe"),
        (("Fetch {url} requiring TLS 1.3 or newer", "Require TLS 1.3 for the request to {url}"), "curl --fail --tlsv1.3 '{url}'", "safe"),
        (("Fetch compressed content from {url} and decompress it automatically", "Request compression from {url} and decode the response"), "curl --fail --compressed '{url}'", "safe"),
        (("Write response headers from {url} to {out}.headers and the body to {out}", "Save both headers and body from {url} in separate files"), "curl --fail --dump-header {out}.headers --output {out} '{url}'", "safe"),
        (("Request {url} only if it changed since {out}", "Perform a conditional download of {url} using {out}'s modification time"), "curl --fail --time-cond {out} --output {out} '{url}'", "safe"),
    ]:
        add_family("curl-http", risk, nl, cmd, HTTP)

    for nl, cmd in [
        (("Query the {type} record for {domain}", "Use dig to look up {domain} type {type}"), "dig {domain} {type}"),
        (("Print only {type} answers for {domain}", "Get the short-form {type} result for {domain}"), "dig +short {domain} {type}"),
        (("Ask DNS server {server} for the {type} record of {domain}", "Query {server} directly for {domain} {type}"), "dig @{server} {domain} {type}"),
        (("Query {domain} {type} over TCP", "Force a TCP DNS lookup for the {type} record of {domain}"), "dig +tcp {domain} {type}"),
        (("Request DNSSEC records while resolving {domain} {type}", "Set the DNSSEC OK bit for a {type} lookup of {domain}"), "dig +dnssec {domain} {type}"),
        (("Trace DNS delegation for {domain}", "Follow the DNS delegation path for {domain}"), "dig +trace {domain}"),
        (("Reverse-resolve {addr}", "Use dig to perform a PTR lookup for {addr}"), "dig -x {addr} +short"),
        (("Query {domain} {type} with drill", "Use drill for the {type} record of {domain}"), "drill {domain} {type}"),
        (("Ask {server} for {domain} {type} using kdig", "Run a kdig query for {domain} {type} against {server}"), "kdig @{server} {domain} {type}"),
        (("Resolve {domain} through the system NSS configuration", "Use getent to look up addresses for {domain}"), "getent ahosts {domain}"),
        (("Show resolver status for the interface associated with {domain}", "Query {domain} with systemd-resolved and display protocol details"), "resolvectl query --legend=yes --protocol=yes {domain}"),
        (("Look up {domain} with host using DNS server {server}", "Query {server} for {domain} using the host utility"), "host {domain} {server}"),
    ]:
        add_family("dns-diagnostics", "safe", nl, cmd, DOMAINS)


def add_network() -> None:
    for nl, cmd, risk in [
        (("Capture 100 packets on {iface} involving host {host}", "Use tcpdump on {iface} to collect 100 packets to or from {host}"), "tcpdump -i {iface} -nn -c 100 host {host}", "caution"),
        (("Capture TCP traffic on {iface} for port {port}", "Monitor TCP port {port} on {iface} without name resolution"), "tcpdump -i {iface} -nn 'tcp port {port}'", "caution"),
        (("Capture traffic for {net} on {iface} into {pcap}", "Write packets on {iface} matching {net} to {pcap}"), "tcpdump -i {iface} -nn -w {pcap} net {net}", "caution"),
        (("Read {pcap} and display packets for port {port}", "Filter saved capture {pcap} for port {port}"), "tcpdump -nn -r {pcap} port {port}", "safe"),
        (("Capture the first 96 bytes of 50 packets on {iface}", "Take a 96-byte snapshot of 50 packets from {iface}"), "tcpdump -i {iface} -nn -s 96 -c 50", "caution"),
        (("Show TCP SYN packets seen on {iface}", "Filter {iface} for TCP packets with SYN set and ACK clear"), "tcpdump -i {iface} -nn 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'", "caution"),
        (("List HTTP host headers in {pcap} with tshark", "Extract HTTP host fields from capture {pcap}"), "tshark -r {pcap} -Y 'http.host' -T fields -e ip.src -e http.host", "safe"),
        (("Show DNS query names and response codes in {pcap}", "Use tshark to extract DNS names and response codes from {pcap}"), "tshark -r {pcap} -Y 'dns' -T fields -e dns.qry.name -e dns.flags.rcode", "safe"),
        (("Capture 25 packets on {iface} with tshark", "Use tshark to collect 25 packets from {iface}"), "tshark -i {iface} -c 25", "caution"),
        (("Run a ten-cycle report-mode MTR to {host}", "Measure the route to {host} with ten noninteractive MTR probes"), "mtr --report --report-cycles 10 --no-dns {host}", "safe"),
        (("Trace the TCP route to {host} on port {port}", "Use traceroute with TCP probes to {host}:{port}"), "traceroute -T -p {port} -n {host}", "safe"),
        (("Trace the path MTU to {host}", "Use tracepath without reverse DNS to diagnose the route to {host}"), "tracepath -n {host}", "safe"),
        (("Send five timestamped ICMP probes to {host}", "Ping {host} five times and print timestamps"), "ping -n -D -c 5 {host}", "safe"),
        (("Show listening TCP sockets for port {port}", "Use ss to list listening TCP endpoints on port {port}"), "ss -ltnp 'sport = :{port}'", "safe"),
        (("Show established TCP connections involving {host}", "List established TCP sockets connected to {host}"), "ss -tnp state established 'dst {host}'", "safe"),
        (("List processes using TCP port {port}", "Use lsof to find owners of TCP port {port}"), "lsof -nP -iTCP:{port}", "safe"),
        (("Perform a TCP connect scan of the top {port} ports on localhost", "Use nmap's unprivileged connect scan for the {port} most common ports on 127.0.0.1"), "nmap -sT --top-ports {port} 127.0.0.1", "caution"),
        (("Check whether documentation host {host} is up without a port scan", "Run nmap host discovery only against {host}"), "nmap -sn {host}", "caution"),
        (("Probe TCP port {port} on documentation host {host}", "Run an nmap connect scan only for port {port} on {host}"), "nmap -sT -p {port} --reason {host}", "caution"),
        (("Identify the service on TCP port {port} of localhost", "Run conservative nmap service detection for localhost port {port}"), "nmap -sT -sV --version-light -p {port} 127.0.0.1", "caution"),
    ]:
        add_family("packet-network-diagnostics", risk, nl, cmd, NETS)


def add_isolation_mac() -> None:
    nsrows = [dict(row, ns=f"lab{i+1}", unit=f"job{i+1}") for i, row in enumerate(NETS)]
    for nl, cmd, risk in [
        (("Show the configured network namespace named {ns}", "Filter the named Linux network namespace list for {ns}"), "ip netns list | grep -F -- {ns}", "safe"),
        (("Create network namespace {ns}", "Add a named Linux network namespace called {ns}"), "ip netns add {ns}", "caution"),
        (("Delete network namespace {ns}", "Remove the named network namespace {ns}"), "ip netns delete {ns}", "destructive"),
        (("Show interfaces inside network namespace {ns}", "Run ip link show in namespace {ns}"), "ip netns exec {ns} ip link show", "safe"),
        (("Run a shell in new user, PID, mount, network, and UTS namespaces named {ns}", "Start an isolated shell with hostname {ns}, mapped root, and a mounted procfs"), "unshare --user --map-root-user --pid --mount --net --uts --fork --mount-proc bash -c 'hostname {ns}; exec bash'", "caution"),
        (("Enter the network namespace of process {port}", "Use nsenter to run a shell in PID {port}'s network namespace"), "nsenter --target {port} --net bash", "caution"),
        (("List namespace links for process {port}", "Show every namespace associated with PID {port}"), "ls -l /proc/{port}/ns", "safe"),
        (("Run sleep in transient unit {unit} with a 256-megabyte memory limit", "Create systemd scope {unit} capped at 256 MB"), "systemd-run --scope --unit={unit} -p MemoryMax=256M sleep 60", "caution"),
        (("Run a CPU-limited command in transient unit {unit}", "Start yes in systemd scope {unit} with a 20 percent CPU quota"), "systemd-run --scope --unit={unit} -p CPUQuota=20% yes", "caution"),
        (("Show lines from the systemd control-group tree containing {unit}", "Filter cgroup-tree output for transient unit {unit}"), "systemd-cgls --all | grep -F -- {unit}", "safe"),
        (("Display live cgroup resource use for one refresh", "Take one batch-mode systemd-cgtop sample for the {unit} context"), "systemd-cgtop --batch --iterations=1 # {unit}", "safe"),
        (("Show cgroup membership for process {port}", "Read PID {port}'s cgroup assignments"), "cat /proc/{port}/cgroup", "safe"),
        (("Show capabilities attached to /usr/bin/{service}", "Inspect file capabilities on /usr/bin/{service}"), "getcap /usr/bin/{service}", "safe"),
        (("Grant /usr/bin/{service} permission to bind low ports", "Set cap_net_bind_service on /usr/bin/{service}"), "setcap cap_net_bind_service=+ep /usr/bin/{service}", "caution"),
        (("Remove all file capabilities from /usr/bin/{service}", "Clear extended capabilities on /usr/bin/{service}"), "setcap -r /usr/bin/{service}", "destructive"),
        (("Print the current process capability sets", "Use capsh to display capability and securebits state for {unit}"), "capsh --print # {unit}", "safe"),
        (("Run id with all capabilities dropped", "Use capsh to execute id after dropping every capability for {unit}"), "capsh --drop=all -- -c id # {unit}", "caution"),
        (("Run /usr/bin/{service} with new privileges disabled", "Use setpriv to prevent gaining privileges while launching /usr/bin/{service}"), "setpriv --no-new-privs /usr/bin/{service}", "caution"),
        (("Show resource limits for process {port}", "Use prlimit to inspect PID {port}'s limits"), "prlimit --pid {port}", "safe"),
        (("Limit open files to {port} while running /usr/bin/{service}", "Launch /usr/bin/{service} with both soft and hard NOFILE set to {port}"), "prlimit --nofile={port}:{port} -- /usr/bin/{service}", "caution"),
    ]:
        add_family("namespaces-cgroups-capabilities", risk, nl, cmd, nsrows)

    for nl, cmd, risk in [
        (("Show audit subsystem status for the {proc} review", "Print the current auditd status before checking {proc}"), "auditctl -s # {proc}", "safe"),
        (("List loaded audit rules while reviewing {proc}", "Display all active audit rules for the {proc} audit"), "auditctl -l # {proc}", "safe"),
        (("Search today's audit events for executable {proc}", "Use ausearch to find today's records involving {proc}"), "ausearch -ts today -x {proc} -i", "safe"),
        (("Summarize failed authentication events from today's audit log for {proc}", "Create an interpreted audit authentication-failure report for the {proc} review"), "aureport --auth --failed --start today --interpret # {proc}", "safe"),
        (("Add an audit watch for {file} that records writes and attribute changes", "Watch {file} for audit write and metadata changes under key config_{proc}"), "auditctl -w {file} -p wa -k config_{proc}", "caution"),
        (("Remove the audit watch for {file}", "Delete the write and attribute audit rule on {file}"), "auditctl -W {file} -p wa -k config_{proc}", "destructive"),
        (("Show whether SELinux is enforcing while checking {proc}", "Print the current SELinux enforcement mode for {proc}"), "getenforce # {proc}", "safe"),
        (("Show detailed SELinux status for the {proc} investigation", "Run sestatus while reviewing {proc}"), "sestatus # {proc}", "safe"),
        (("Show SELinux labels on {file}", "List the security context assigned to {file}"), "ls -lZ {file}", "safe"),
        (("Preview SELinux relabeling changes for {file}", "Dry-run restorecon verbosely on {file}"), "restorecon -n -v {file}", "safe"),
        (("List SELinux file-context rules matching {proc}", "Search managed SELinux path mappings for {proc}"), "semanage fcontext -l | grep -F -- {proc}", "safe"),
        (("List SELinux booleans related to {proc}", "Search SELinux boolean state for {proc}"), "getsebool -a | grep -F -- {proc}", "safe"),
        (("Show AppArmor profile status for {proc}", "Filter aa-status output for the {proc} profile"), "aa-status | grep -F -- {proc}", "safe"),
        (("Put AppArmor profile /etc/apparmor.d/usr.sbin.{proc} into complain mode", "Switch the {proc} AppArmor profile to logging-only complain mode"), "aa-complain /etc/apparmor.d/usr.sbin.{proc}", "caution"),
        (("Reload AppArmor profile /etc/apparmor.d/usr.sbin.{proc}", "Parse and replace the loaded AppArmor profile for {proc}"), "apparmor_parser -r /etc/apparmor.d/usr.sbin.{proc}", "caution"),
        (("Show recent kernel denials mentioning {proc}", "Search kernel journal AVC or AppArmor denials for {proc}"), "journalctl -k --since today | grep -Ei '(avc|apparmor).*{proc}'", "safe"),
    ]:
        add_family("audit-selinux-apparmor", risk, nl, cmd, [{**p, **PATHS[i]} for i, p in enumerate(PROCS)])


def add_process_shell() -> None:
    for nl, cmd, risk in [
        (("Show PID, parent, state, elapsed time, and command for {proc}", "List process-tree details for every {proc} process"), "ps -C {proc} -o pid,ppid,state,etime,args --forest", "safe"),
        (("Find exact PIDs and command lines for {proc}", "Use pgrep to list {proc} PIDs with full commands"), "pgrep -a -x {proc}", "safe"),
        (("Show status information for PID {pid}", "Read the procfs status file for process {pid}"), "cat /proc/{pid}/status", "safe"),
        (("Print the executable path for PID {pid}", "Resolve /proc/{pid}/exe"), "readlink -f /proc/{pid}/exe", "safe"),
        (("Print the working directory of PID {pid}", "Resolve process {pid}'s current working directory"), "readlink -f /proc/{pid}/cwd", "safe"),
        (("List open file descriptors for PID {pid}", "Show PID {pid}'s file-descriptor symlinks"), "ls -l /proc/{pid}/fd", "safe"),
        (("Display PID {pid}'s command line with arguments separated by spaces", "Decode the NUL-separated command line for process {pid}"), "tr '\\0' ' ' </proc/{pid}/cmdline", "safe"),
        (("Display sorted environment entries for PID {pid}", "Decode and sort process {pid}'s procfs environment"), "tr '\\0' '\\n' </proc/{pid}/environ | sort", "caution"),
        (("Show memory-map summary for PID {pid}", "Read smaps_rollup for process {pid}"), "cat /proc/{pid}/smaps_rollup", "safe"),
        (("Show I/O counters for PID {pid}", "Read process {pid}'s procfs I/O statistics"), "cat /proc/{pid}/io", "safe"),
        (("Show operating-system limits for PID {pid}", "Read the limits applied to process {pid}"), "cat /proc/{pid}/limits", "safe"),
        (("List threads belonging to PID {pid}", "Show task IDs and names for process {pid}"), "ps -T -p {pid} -o pid,tid,comm,state", "safe"),
        (("Sample CPU, memory, and I/O statistics for PID {pid} five times", "Use pidstat on process {pid} once per second for five samples"), "pidstat -p {pid} -rud 1 5", "safe"),
        (("List open files for PID {pid}", "Use lsof to inspect process {pid}'s open resources"), "lsof -nP -p {pid}", "safe"),
        (("Trace file-related system calls made by PID {pid}", "Attach strace to process {pid}, following file syscalls"), "strace -f -e trace=%file -p {pid}", "caution"),
        (("Send signal {signal} to every exact {proc} process", "Signal processes named exactly {proc} with {signal}"), "pkill --signal {signal} --exact {proc}", "caution"),
    ]:
        add_family("process-procfs", risk, nl, cmd, PROCS)

    shellrows = [
        {**PATHS[i], **PROCS[i], "var": var, "default": default, "suffix": suffix}
        for i, (var, default, suffix) in enumerate(zip(
            ["CONFIG", "PORT", "HOST", "MODE", "LOG_DIR", "TIMEOUT", "WORKERS", "CACHE_DIR", "REGION", "RETRIES", "FORMAT", "OUTPUT", "TOKEN_FILE", "ENDPOINT", "PROFILE", "STATE_DIR"],
            ["/etc/app.conf", "8080", "localhost", "safe", "/var/log/app", "30", "4", "/var/cache/app", "us-test-1", "3", "json", "/tmp/result", "/run/secrets/token", "https://api.example.test", "staging", "/var/lib/app"],
            ["yaml", "txt", "json", "log", "bak", "tmp", "csv", "conf", "dat", "out", "gz", "lock", "token", "url", "profile", "state"],
        ))
    ]
    for nl, cmd, risk in [
        (("Run a strict Bash command that prints {var}", "Print {var} from a shell with errexit, nounset, and pipefail enabled"), r"""bash -c 'set -Eeuo pipefail; printf "%s\n" "${{{var}}}"'""", "safe"),
        (("Require environment variable {var} and print a useful error if missing", "Exit with a message unless {var} is set and nonempty"), r"""bash -c ': "${{{var}:?{var} must be set}}"; printf "%s\n" "${{{var}}}"'""", "safe"),
        (("Print {var}, using {default} when it is unset or empty", "Apply a Bash default value of {default} to {var}"), r"""bash -c 'printf "%s\n" "${{{var}:-{default}}}"'""", "safe"),
        (("Remove the shortest .{suffix} suffix from variable {var}", "Use Bash parameter expansion to strip .{suffix} from the end of {var}"), r"""bash -c 'printf "%s\n" "${{{var}%.{suffix}}}"'""", "safe"),
        (("Print only the basename portion of variable {var}", "Use Bash parameter expansion to remove the longest directory prefix from {var}"), r"""bash -c 'printf "%s\n" "${{{var}##*/}}"'""", "safe"),
        (("Read {file} line by line without interpreting backslashes", "Use a robust IFS read loop over {file}"), r"""while IFS= read -r line || [[ -n $line ]]; do printf '%s\n' "$line"; done <{file}""", "safe"),
        (("Load all lines from {file} into a Bash array", "Use mapfile to read {file} into the lines array"), r"""mapfile -t lines <{file}; printf '%s\n' "${{lines[@]}}" """, "safe"),
        (("Store matching .{suffix} files under {path} in an array without literal unmatched globs", "Enable nullglob and collect {path}/*.{suffix} into a Bash array"), r"""bash -c 'shopt -s nullglob; files=({path}/*.{suffix}); printf "%s\n" "${{files[@]}}"'""", "safe"),
        (("Print every argument with shell-safe quoting", "Use Bash printf percent-q to serialize all positional arguments for the {var} context"), r"""bash -c 'printf "%q\n" "$@"' _ "${{{var}:-{default}}}" {file}""", "safe"),
        (("Create a {var}-prefixed temporary directory and remove it automatically on exit", "Use mktemp with an EXIT trap for the {var} workspace"), r"""bash -c 'tmp=$(mktemp -d "/tmp/{var}.XXXXXX"); cleanup() {{ rm -rf -- "$tmp"; }}; trap cleanup EXIT; printf "%s\n" "$tmp"'""", "caution"),
        (("On exit, print the status code and context {var}", "Install a Bash EXIT trap that reports the final status for {var}"), r"""bash -c 'report() {{ status=$?; printf "exit=%d context=%s\n" "$status" "{var}"; }}; trap report EXIT; true'""", "safe"),
        (("Forward TERM and INT to background PID {pid} and wait for it", "Run sleep in the background with signal-forwarding traps for process context {pid}"), r"""bash -c 'sleep 60 & child=$!; forward() {{ kill -TERM "$child" 2>/dev/null; }}; trap forward TERM INT; wait "$child"' # {pid}""", "caution"),
        (("Run a command under an exclusive lock file for {var}", "Acquire /tmp/{var}.lock without waiting before printing the context"), r"""flock -n /tmp/{var}.lock bash -c 'printf "%s\n" {var}'""", "safe"),
        (("Wait for background jobs and report the first one to finish", "Use Bash wait -n while processing {file}"), r"""bash -c 'sleep 1 & sleep 2 & wait -n; printf "first job finished: %s\n" {file}'""", "safe"),
        (("Parse -f and -n options with getopts for the {var} script", "Use getopts to assign a file and numeric value for {var}"), r"""bash -c 'while getopts "f:n:" opt; do case $opt in f) file=$OPTARG;; n) number=$OPTARG;; esac; done; printf "%s %s\n" "${{file:-{file}}}" "${{number:-{default}}}"'""", "safe"),
        (("Associate key {var} with value {default} in a Bash map", "Create an associative array and retrieve the {var} entry"), r"""bash -c 'declare -A cfg=([{var}]={default}); printf "%s\n" "${{cfg[{var}]}}"'""", "safe"),
        (("Split the colon-separated value of {var} into an array", "Use a temporary IFS to parse {var} on colons"), r"""bash -c 'IFS=: read -r -a parts <<< "${{{var}:-{default}}}"; printf "%s\n" "${{parts[@]}}"'""", "safe"),
        (("Capture output and status from a command without losing the exit code", "Store both output and return status while checking {file}"), r"""bash -c 'set +e; output=$(test -r {file} 2>&1); status=$?; set -e; printf "status=%d output=%s\n" "$status" "$output"'""", "safe"),
        (("Print each pipeline component's status after searching {file}", "Show PIPESTATUS after grep and sort process {file}"), r"""bash -c 'set -o pipefail; grep -F -- {var} {file} | sort -u; printf "%s\n" "${{PIPESTATUS[*]}}"'""", "safe"),
        (("Compare sorted {file} with {path}/expected.{suffix} using process substitution", "Use comm and process substitution to compare two sorted files for {var}"), "comm -3 <(sort {file}) <(sort {path}/expected.{suffix})", "safe"),
        (("Limit a search of {file} for {var} to ten seconds", "Terminate grep if searching {file} for {var} takes longer than ten seconds"), "timeout --signal=TERM 10s grep -F -- {var} {file}", "safe"),
        (("Retry reading {file} up to three times with increasing delays", "Use a three-attempt Bash retry loop to test whether {file} is readable"), r"""bash -c 'for attempt in {{1..3}}; do test -r {file} && exit 0; sleep "$attempt"; done; exit 1'""", "safe"),
    ]:
        add_family("robust-bash", risk, nl, cmd, shellrows)


def add_files_events() -> None:
    for nl, cmd, risk in [
        (("Find .{event} files under {path} safely when names contain spaces", "Print NUL-delimited .{event} paths below {path}"), "find {path} -type f -name '*.{event}' -print0", "safe"),
        (("Compute checksums for files under {path} with NUL-safe xargs", "Hash every regular file below {path} even when names contain whitespace"), "find {path} -type f -print0 | xargs -0 -r sha256sum", "safe"),
        (("Run stat once per file under {path} without xargs", "Use find -exec to print metadata for each file below {path}"), "find {path} -type f -exec stat --format='%n %s %y' -- '{{}}' ';'", "safe"),
        (("Batch files under {path} into as few chmod invocations as possible", "Use find -exec plus to set regular files below {path} to mode 0640"), "find {path} -type f -exec chmod 0640 -- '{{}}' +", "caution"),
        (("Find regular files larger than {pid} kilobytes under {path}", "List files below {path} whose size exceeds {pid} KiB"), "find {path} -type f -size +{pid}k -print", "safe"),
        (("Find files changed within the last {pid} minutes under {path}", "List regular files below {path} modified less than {pid} minutes ago"), "find {path} -type f -mmin -{pid} -print", "safe"),
        (("Find files owned by {user} under {path}", "List regular files below {path} whose owner is {user}"), "find {path} -type f -user {user} -print", "safe"),
        (("Find world-writable files under {path} without crossing filesystems", "List world-writable regular files below {path} on the same mount"), "find {path} -xdev -type f -perm -0002 -print", "safe"),
        (("Find setuid or setgid files under {path}", "Audit {path} for regular files with either setuid or setgid set"), "find {path} -xdev -type f '(' -perm -4000 -o -perm -2000 ')' -print", "safe"),
        (("Search {path} while pruning .git directories", "Find regular files below {path} but skip every .git subtree"), "find {path} -type d -name .git -prune -o -type f -print", "safe"),
        (("Delete empty directories under {path} from deepest to shallowest", "Remove empty directory trees below {path}"), "find {path} -depth -type d -empty -delete", "destructive"),
        (("Delete .{event} files older than {pid} days under {path}", "Remove regular .{event} files below {path} whose modification time exceeds {pid} days"), "find {path} -type f -name '*.{event}' -mtime +{pid} -delete", "destructive"),
        (("Show the ACL on {file}", "Read access-control-list entries for {file}"), "getfacl --absolute-names {file}", "safe"),
        (("Grant user {user} read access to {file} with an ACL", "Add an ACL entry allowing {user} to read {file}"), "setfacl -m u:{user}:r {file}", "caution"),
        (("Remove the ACL entry for user {user} from {file}", "Delete {user}'s named ACL entry on {file}"), "setfacl -x u:{user} {file}", "destructive"),
        (("Set a default ACL giving group {group} read and execute on {path}", "Add an inherited group ACL for {group} on directory {path}"), "setfacl -m d:g:{group}:rx {path}", "caution"),
        (("List extended attributes and values on {file}", "Recursively decode xattrs attached to {file}"), "getfattr -d -m - {file}", "safe"),
        (("Set user.purpose extended attribute to {event} on {file}", "Attach xattr user.purpose={event} to {file}"), "setfattr -n user.purpose -v {event} {file}", "caution"),
        (("Remove user.purpose extended attribute from {file}", "Delete the user.purpose xattr on {file}"), "setfattr -x user.purpose {file}", "destructive"),
        (("Archive {path} while preserving ACLs and extended attributes", "Create backup of {path} with rsync ACL and xattr preservation"), "rsync -aAX {path}/ backup{path}/", "caution"),
    ]:
        add_family("find-acl-xattr", risk, nl, cmd, [{**p, **PROCS[i]} for i, p in enumerate(PATHS)])

    for nl, cmd, risk in [
        (("Wait for a {event} event on {file}", "Monitor {file} until inotify reports {event}"), "inotifywait --event {event} --format '%w%f %e' {file}", "safe"),
        (("Recursively monitor {path} for create, modify, and delete events", "Watch the entire {path} tree for file creation, changes, and deletion"), "inotifywait --monitor --recursive --event create --event modify --event delete --format '%T %e %w%f' --timefmt '%FT%T%z' {path}", "safe"),
        (("Wait at most {pid} seconds for a {event} event under {path}", "Use inotifywait with a {pid}-second timeout on {path}"), "inotifywait --timeout {pid} --event {event} {path}", "safe"),
        (("Monitor {path} recursively but exclude temporary .{event} files", "Watch {path} while ignoring paths ending in .{event}"), "inotifywait --monitor --recursive --exclude '\\.{event}$' {path}", "safe"),
        (("Print a parsable NUL-terminated record for each create event in {path}", "Monitor creates in {path} and delimit inotify output records with NUL"), "inotifywait --monitor --event create --format '%w%f%0' --no-newline {path}", "safe"),
        (("Watch {file} for attribute changes", "Monitor only attrib events on {file}"), "inotifywait --monitor --event attrib --format '%e %w%f' {file}", "safe"),
        (("Show processes currently accessing {path}", "Use fuser to list PIDs that have {path} open"), "fuser -v {path}", "safe"),
        (("Show which processes have {file} open", "List open-file records for {file}"), "lsof -- {file}", "safe"),
    ]:
        add_family("inotify-file-events", risk, nl, cmd, [{**p, **PROCS[i]} for i, p in enumerate(PATHS)])


def add_scheduling_locale_mail_hardware() -> None:
    schedrows = [{**p, "pid": 101 + i, "queue": chr(ord("a") + i), "minute": (i * 5) % 60, "hour": (i + 1) % 24, "unit": f"job-{i+1}"} for i, p in enumerate(PATHS)]
    for nl, cmd, risk in [
        (("List the current user's cron entries that mention {file}", "Filter this user's crontab for jobs containing {file}"), "crontab -l | grep -F -- {file}", "safe"),
        (("List cron jobs for user {user}", "Display {user}'s crontab"), "crontab -u {user} -l", "safe"),
        (("Install a cron entry running {file} at {hour}:{minute:0>2}", "Append a daily {hour}:{minute:0>2} cron job for {file} without duplicating it"), "(crontab -l 2>/dev/null; printf '%s\\n' '{minute} {hour} * * * {file}') | awk '!seen[$0]++' | crontab -", "caution"),
        (("Test which scripts run-parts would execute in {path}", "Dry-run the run-parts selection for {path}"), "run-parts --test {path}", "safe"),
        (("List queued at jobs in queue {queue}", "Show only at jobs assigned to queue {queue}"), "atq -q {queue}", "safe"),
        (("Show the commands in at job {pid}", "Print queued at job number {pid}"), "at -c {pid}", "safe"),
        (("Schedule a readability check for {file} at {hour}:{minute:0>2} tomorrow", "Queue an at job that tests whether {file} is readable tomorrow at {hour}:{minute:0>2}"), "printf '%s\\n' \"test -r '{file}'\" | at {hour}:{minute:0>2} tomorrow", "caution"),
        (("Remove queued at job {pid}", "Delete at job number {pid}"), "atrm {pid}", "destructive"),
        (("List systemd timers, including inactive ones, whose unit name starts with {unit}", "Show all timers matching the {unit} unit prefix"), "systemctl list-timers --all '{unit}*'", "safe"),
        (("Show the next and last activation times for timer {unit}.timer", "Inspect systemd timer {unit}.timer"), "systemctl show {unit}.timer -p NextElapseUSecRealtime -p LastTriggerUSec", "safe"),
    ]:
        add_family("cron-at-timers", risk, nl, cmd, schedrows)

    tzrows = [
        {"tz": tz, "stamp": stamp, "locale": locale, "encoding": encoding, "file": FILES[i]["file"]}
        for i, (tz, stamp, locale, encoding) in enumerate(zip(
            ["UTC", "America/Chicago", "Europe/London", "Asia/Tokyo", "Australia/Sydney", "Europe/Berlin", "America/New_York", "Asia/Kolkata", "Pacific/Auckland", "Africa/Johannesburg", "America/Los_Angeles", "Europe/Paris"],
            ["2026-01-15T12:30:00Z", "2026-02-20T18:45:00Z", "2026-03-01T00:00:00Z", "2026-04-10T09:15:00Z", "2026-05-05T22:10:00Z", "2026-06-30T16:00:00Z", "2026-07-04T14:20:00Z", "2026-08-12T05:35:00Z", "2026-09-21T11:11:00Z", "2026-10-31T23:59:00Z", "2026-11-26T08:00:00Z", "2026-12-24T19:30:00Z"],
            ["C", "en_US.UTF-8", "en_GB.UTF-8", "ja_JP.UTF-8", "en_AU.UTF-8", "de_DE.UTF-8", "en_US.UTF-8", "en_IN.UTF-8", "en_NZ.UTF-8", "en_ZA.UTF-8", "en_US.UTF-8", "fr_FR.UTF-8"],
            ["ISO-8859-1", "UTF-16LE", "WINDOWS-1252", "SHIFT_JIS", "UTF-16BE", "ISO-8859-15", "ASCII", "UTF-32LE", "MACINTOSH", "CP850", "KOI8-R", "UTF-7"],
        ))
    ]
    for nl, cmd in [
        (("Show {stamp} in timezone {tz}", "Convert timestamp {stamp} for display in {tz}"), "TZ={tz} date --date='{stamp}' --iso-8601=seconds"),
        (("Convert {stamp} to Unix epoch seconds", "Print epoch seconds for timestamp {stamp}"), "date --date='{stamp}' +%s"),
        (("Parse {stamp} and print it as UTC RFC 3339", "Normalize {stamp} to a UTC date-time string"), "date --utc --date='{stamp}' --rfc-3339=seconds"),
        (("Show the calendar for the month containing {stamp}", "Print the month calendar associated with {stamp}"), "cal $(date --date='{stamp}' '+%m %Y')"),
        (("List installed locales matching {locale}", "Search available locale names for {locale}"), "locale -a | grep -i -F -- '{locale}'"),
        (("Print locale settings with {locale} selected", "Run locale under {locale}"), "LC_ALL={locale} locale",),
        (("Sort {file} bytewise using the C locale", "Perform deterministic C-locale sorting of {file}"), "LC_ALL=C sort {file}"),
        (("Convert {file} from {encoding} to UTF-8", "Use iconv to decode {encoding} text in {file} as UTF-8"), "iconv -f {encoding} -t UTF-8 {file}"),
        (("Show system clock, timezone, and synchronization state for {tz}", "Display timedatectl status while reviewing timezone {tz}"), "timedatectl status # {tz}"),
        (("Show available timezones matching {tz}", "Filter timedatectl's timezone list for {tz}"), "timedatectl list-timezones | grep -F -- '{tz}'"),
        (("Show chrony time sources for the {tz} clock review", "Print verbose chrony source state while checking {tz}"), "chronyc sources -v # {tz}"),
        (("Show chrony's system clock tracking report for {tz}", "Print chrony tracking data while checking {tz}"), "chronyc tracking # {tz}"),
    ]:
        add_family("locale-time", "safe", nl, cmd, tzrows)

    mailrows = [
        {"recipient": who, "sender": sender, "subject": subject, "server": server, "file": FILES[i]["file"], "queue": i + 1}
        for i, (who, sender, subject, server) in enumerate(zip(
            ["ops@example.test", "security@example.test", "alerts@example.test", "release@example.test", "backup@example.test", "audit@example.test", "admin@example.test", "noc@example.test", "dba@example.test", "mailops@example.test", "support@example.test", "oncall@example.test"],
            ["monitor@example.test", "scanner@example.test", "watcher@example.test", "ci@example.test", "backupd@example.test", "auditd@example.test", "root@example.test", "router@example.test", "database@example.test", "postmaster@example.test", "helpdesk@example.test", "pager@example.test"],
            ["Service health", "Security report", "Threshold alert", "Release ready", "Backup complete", "Audit summary", "System notice", "Network report", "Database status", "Queue test", "Support bundle", "On-call test"],
            ["mail.example.test", "smtp.example.test", "relay.example.test", "mail.example.test", "smtp.example.test", "relay.example.test", "mail.example.test", "smtp.example.test", "relay.example.test", "mail.example.test", "smtp.example.test", "relay.example.test"],
        ))
    ]
    for nl, cmd, risk in [
        (("List the local mail queue for {server}", "Show queued mail while checking {server}"), "mailq # {server}", "safe"),
        (("List the Postfix queue in machine-readable form for {server}", "Use postqueue JSON output while reviewing {server}"), "postqueue -j # {server}", "safe"),
        (("Show mail-service journal entries since today for {server}", "Read today's Postfix logs while reviewing {server}"), "journalctl -u postfix --since today # {server}", "safe"),
        (("Test an SMTP connection to {server} without sending a message", "Use swaks to stop after CONNECT to {server}"), "swaks --server {server} --quit-after CONNECT", "safe"),
        (("Test the SMTP EHLO response from {server}", "Use swaks to stop after EHLO against {server}"), "swaks --server {server} --ehlo example.test --quit-after EHLO", "safe"),
        (("Inspect STARTTLS on SMTP server {server}:25", "Negotiate SMTP STARTTLS with {server} and show the certificate"), "openssl s_client -starttls smtp -connect {server}:25 -servername {server} </dev/null", "safe"),
        (("Send {file} to {recipient} with subject {subject}", "Mail {file} as the message body to {recipient}"), "mailx -s '{subject}' {recipient} <{file}", "caution"),
        (("Send a test SMTP message from {sender} to {recipient} through {server}", "Use swaks to deliver a test titled {subject} via {server}"), "swaks --server {server} --from {sender} --to {recipient} --header 'Subject: {subject}' --body 'Test message'", "caution"),
        (("Base64-encode {file} as MIME with 76-character lines", "Create wrapped MIME Base64 content from {file}"), "base64 --wrap=76 {file}", "safe"),
        (("Decode MIME Base64 file {file}.b64", "Recover binary content from {file}.b64"), "base64 --decode {file}.b64", "safe"),
        (("Show message headers from the first local mailbox message for {recipient}", "Use mutt to inspect message headers in {recipient}'s local mailbox"), "mutt -f /var/mail/{recipient} -e 'push <display-toggle-weed><exit>'", "safe"),
        (("Request immediate delivery of Postfix mail queued for {server}", "Flush queued Postfix messages whose next-hop site is {server}"), "postqueue -s {server}", "caution"),
    ]:
        add_family("mail-diagnostics", risk, nl, cmd, mailrows)

    hwrows = [
        {"device": dev, "pci": pci, "usb": usb, "module": module, "iface": iface, "cpu": cpu, "event": event}
        for dev, pci, usb, module, iface, cpu, event in zip(
            ["/dev/sda", "/dev/sdb", "/dev/nvme0n1", "/dev/nvme1n1", "/dev/vda", "/dev/vdb", "/dev/mmcblk0", "/dev/sdc", "/dev/sdd", "/dev/nvme2n1", "/dev/xvda", "/dev/loop0"],
            ["0000:00:1f.6", "0000:01:00.0", "0000:02:00.0", "0000:03:00.0", "0000:04:00.0", "0000:05:00.0", "0000:06:00.0", "0000:07:00.0", "0000:08:00.0", "0000:09:00.0", "0000:0a:00.0", "0000:0b:00.0"],
            ["1d6b:0002", "1d6b:0003", "046d:c534", "0781:5583", "8087:0026", "0bda:8153", "1058:25a2", "05e3:0610", "04f2:b725", "0cf3:e300", "2109:2817", "174c:55aa"],
            ["e1000e", "ixgbe", "nvme", "ahci", "virtio_blk", "virtio_net", "mmc_block", "uas", "xhci_hcd", "i915", "kvm_intel", "loop"],
            ["eth0", "ens3", "enp5s0", "eno1", "bond0", "br0", "wlan0", "wg0", "tun0", "docker0", "enp2s0", "veth0"],
            range(12),
            ["error", "warning", "timeout", "thermal", "oom", "reset", "firmware", "I/O", "link", "segfault", "blocked", "corruption"],
        )
    ]
    for nl, cmd, risk in [
        (("Show topology details for logical CPU {cpu}", "Select logical CPU {cpu} from lscpu's extended table"), "lscpu -e=CPU,NODE,SOCKET,CORE,ONLINE | awk 'NR == 1 || $1 == {cpu}'", "safe"),
        (("Show block devices, filesystems, UUIDs, and mount points for {device}", "List storage topology while reviewing {device}"), "lsblk -o NAME,TYPE,SIZE,FSTYPE,UUID,MOUNTPOINTS {device}", "safe"),
        (("Show udev attributes for block device {device}", "Query all udev properties for {device}"), "udevadm info --query=all --name={device}", "safe"),
        (("Show PCI device {pci} with its kernel driver", "Inspect verbose PCI details and driver binding for {pci}"), "lspci -s {pci} -nnk", "safe"),
        (("Show verbose USB descriptor information for device {usb}", "Inspect lsusb details for USB ID {usb}"), "lsusb -v -d {usb}", "safe"),
        (("Show metadata and parameters for kernel module {module}", "Inspect module {module} with modinfo"), "modinfo {module}", "safe"),
        (("Show whether kernel module {module} is loaded", "Search lsmod for exact module {module}"), r"""lsmod | awk '$1 == "{module}"'""", "safe"),
        (("Show kernel messages from this boot mentioning {event}", "Search this boot's kernel journal for {event}"), "journalctl -k -b | grep -i -F -- '{event}'", "safe"),
        (("Follow new kernel messages mentioning {event}", "Stream kernel journal entries and filter for {event}"), "journalctl -k -f | grep --line-buffered -i -F -- '{event}'", "safe"),
        (("Show network-driver and firmware details for {iface}", "Query ethtool driver information on {iface}"), "ethtool -i {iface}", "safe"),
        (("Show link settings for interface {iface}", "Inspect speed, duplex, and link state on {iface}"), "ethtool {iface}", "safe"),
        (("Show interface statistics for {iface}", "Print extended NIC counters for {iface}"), "ethtool -S {iface}", "safe"),
        (("Show mounted filesystems backed by {device}", "Use findmnt to locate mountpoints sourced from {device}"), "findmnt --source {device}", "safe"),
        (("Show I/O statistics for {device} once per second for five samples", "Collect extended iostat samples for {device}"), "iostat -xz {device} 1 5", "safe"),
        (("Show temperatures and fan readings while reviewing {device}", "Read hardware sensors for the {device} diagnostic"), "sensors # {device}", "safe"),
        (("Show NUMA topology for CPU {cpu}", "Print numactl hardware layout while reviewing CPU {cpu}"), "numactl --hardware # CPU {cpu}", "safe"),
        (("Show mitigations reported for CPU {cpu}", "Read kernel vulnerability status files while checking CPU {cpu}"), "grep -H . /sys/devices/system/cpu/vulnerabilities/* # CPU {cpu}", "safe"),
        (("Show current and available frequency data for CPU {cpu}", "Inspect cpufreq information for logical CPU {cpu}"), "cpupower -c {cpu} frequency-info", "safe"),
        (("Count hardware and software events while running true on CPU {cpu}", "Pin a minimal perf stat command to logical CPU {cpu}"), "taskset -c {cpu} perf stat -e cycles,instructions,context-switches true", "safe"),
        (("Show the current value of kernel.printk while reviewing {event}", "Read sysctl kernel.printk for the {event} investigation"), "sysctl kernel.printk # {event}", "safe"),
        (("Show boot command-line arguments mentioning {module}", "Split the kernel command line and filter for module name {module}"), "tr ' ' '\\n' </proc/cmdline | grep -F -- {module}", "safe"),
    ]:
        add_family("hardware-kernel-diagnostics", risk, nl, cmd, hwrows)

    smartrows = [
        row
        for row in hwrows
        if row["device"].startswith(("/dev/sd", "/dev/nvme"))
    ]
    add_family(
        "hardware-kernel-diagnostics",
        "safe",
        ("Show SMART health information for {device}", "Read all SMART data from {device}"),
        "smartctl --all {device}",
        smartrows,
    )
    add_family(
        "hardware-kernel-diagnostics",
        "caution",
        (
            "Run a non-destructive short SMART self-test on {device}",
            "Start the short built-in device test for {device}",
        ),
        "smartctl --test=short {device}",
        smartrows,
    )
    add_family(
        "hardware-kernel-diagnostics",
        "safe",
        ("Show NVMe SMART log for {device}", "Read health telemetry from NVMe namespace {device}"),
        "nvme smart-log {device}",
        [row for row in hwrows if row["device"].startswith("/dev/nvme")],
    )


def deduplicate(items: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    """Keep only records that introduce both a new prompt and a new command."""
    seen_bash: set[str] = set()
    seen_nl: set[str] = set()
    result: list[dict[str, str]] = []
    for item in items:
        if item["bash"] in seen_bash or item["nl"] in seen_nl:
            continue
        seen_bash.add(item["bash"])
        seen_nl.add(item["nl"])
        result.append(item)
    return result


def validate(items: Sequence[Mapping[str, str]]) -> dict[str, object]:
    required = {"nl", "bash", "category", "risk", "source", "family"}
    for index, item in enumerate(items):
        if set(item) != required:
            raise ValueError(f"item {index} has wrong schema: {set(item)}")
        if not item["nl"].strip() or not item["bash"].strip():
            raise ValueError(f"item {index} contains an empty field")
        if "\n" in item["nl"] or "\r" in item["nl"] or "\n" in item["bash"] or "\r" in item["bash"]:
            raise ValueError(f"item {index} is not one line")
        if item["risk"] not in ALLOWED_RISKS or item["source"] != "manual-curation":
            raise ValueError(f"item {index} has invalid provenance metadata")
    bash_values = [item["bash"] for item in items]
    nl_values = [item["nl"] for item in items]
    if len(set(bash_values)) != len(bash_values):
        duplicates = [value for value, count in Counter(bash_values).items() if count > 1][:5]
        raise ValueError(f"duplicate commands: {duplicates}")
    if len(set(nl_values)) != len(nl_values):
        duplicates = [value for value, count in Counter(nl_values).items() if count > 1][:5]
        raise ValueError(f"duplicate prompts: {duplicates}")
    if len(items) < 3600:
        raise ValueError(f"only generated {len(items)} examples; need at least 3600")
    return {
        "examples": len(items),
        "categories": dict(sorted(Counter(x["category"] for x in items).items())),
        "risks": dict(sorted(Counter(x["risk"] for x in items).items())),
        "unique_bash": len(set(bash_values)),
        "unique_nl": len(set(nl_values)),
        "families": len(set(x["family"] for x in items)),
    }


def main() -> None:
    add_crypto()
    add_ssh_http_dns()
    add_network()
    add_isolation_mac()
    add_process_shell()
    add_files_events()
    add_scheduling_locale_mail_hardware()
    unique_examples = deduplicate(examples)
    summary = validate(unique_examples)
    summary["removed_collisions"] = len(examples) - len(unique_examples)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(unique_examples, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
