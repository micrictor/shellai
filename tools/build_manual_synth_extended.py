#!/usr/bin/env python3
"""Build the second manually authored, gap-focused NL-to-Bash corpus shard.

The operation templates below are deliberately authored rather than sampled
from another model. Deterministic expansion supplies realistic, distinct
operational contexts while preserving the semantics of each authored family.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "manual_synth_extended.json"
ALLOWED_RISKS = {"safe", "caution", "destructive"}
ROWS: list[dict[str, str]] = []
SEEN_NL: set[str] = set()
SEEN_BASH: set[str] = set()

APPS = [
    "api", "billing", "catalog", "checkout", "events", "gateway",
    "identity", "ingest", "ledger", "mailer", "metrics", "mobile",
    "orders", "payments", "profiles", "reports", "scheduler", "search",
    "sessions", "shipping", "support", "telemetry", "web", "worker",
]
PACKAGES = [
    "nginx", "curl", "ripgrep", "jq", "git", "openssl", "tmux", "rsync",
    "postgresql", "redis", "podman", "buildah", "ansible", "sqlite", "python3",
    "nodejs", "ruby", "php", "elixir", "ghc", "lua", "shellcheck", "graphviz",
    "mosquitto", "haproxy", "bind-utils", "strace", "lsof", "nmap", "skopeo",
    "restic", "borgbackup", "clamav", "yara", "osquery", "semgrep", "certbot",
    "flatpak", "syncthing", "vagrant", "qemu", "libvirt", "rclone", "pandoc",
    "gdal", "exiftool", "bpftrace", "ipmitool",
]
SERVICES = [
    "http", "https", "ssh", "dns", "smtp", "imap", "postgresql", "mysql",
    "redis", "amqp", "mqtt", "nats", "kafka", "grafana", "prometheus", "ntp",
    "dhcp", "samba", "nfs", "ceph", "glusterfs", "consul", "nomad", "vault",
]


def build_contexts() -> list[dict[str, str | int]]:
    disks = [f"/dev/sd{chr(ord('a') + i)}" for i in range(26)] + [
        f"/dev/nvme{i}n1" for i in range(22)
    ]
    contexts = []
    for index in range(48):
        app = APPS[index % len(APPS)]
        env = "staging" if index < 24 else "production"
        serial_port = 5554 + index * 2
        contexts.append(
            {
                "i": index + 1,
                "app": app,
                "env": env,
                "name": f"{app}-{env}-{index + 1}",
                "host": f"{app}-{env}-{index + 1}.example.test",
                "domain": f"{app}-{env}-{index + 1}.example.test",
                "ip": f"192.0.2.{index + 1}",
                "ipv6": f"2001:db8::{index + 1:x}",
                "port": 20000 + index,
                "iface": f"enp{index + 1}s0",
                "mac": f"02:00:00:00:{index // 256:02x}:{index % 256:02x}",
                "disk": disks[index],
                "md": f"/dev/md{index}",
                "mapper": f"{app}_{env}_{index + 1}",
                "path": f"/srv/{env}/{app}-{index + 1}",
                "file": f"/srv/{env}/{app}-{index + 1}/manifest-{index + 1}.json",
                "config": f"/etc/{app}/{env}-{index + 1}.conf",
                "repo": f"services/{app}-{env}-{index + 1}",
                "user": f"{app}-operator-{index + 1}",
                "group": f"{app}-team-{index + 1}",
                "pkg": PACKAGES[index],
                "service": SERVICES[index % len(SERVICES)],
                "zone": f"{env}-{app}-{index + 1}",
                "queue": f"{app}.{env}.queue.{index + 1}",
                "topic": f"{app}.{env}.events.{index + 1}",
                "stream": f"{app}_{env}_stream_{index + 1}",
                "consumer": f"{app}_{env}_consumer_{index + 1}",
                "vhost": f"/{env}/{app}-{index + 1}",
                "database": f"{app}_{env}_{index + 1}",
                "table": f"{app}_records_{index + 1}",
                "bucket": f"{app}-{env}-archive-{index + 1}",
                "volume": f"{app}_{env}_vol_{index + 1}",
                "pool": f"{app}_{env}_pool_{index + 1}",
                "image": f"registry.example.test/{env}/{app}:v{index + 1}.0",
                "profile": f"{app}-{env}-{index + 1}",
                "cluster": f"{app}-{env}-cluster-{index + 1}",
                "namespace": f"{app}-{env}-{index + 1}",
                "job": f"{app}-{env}-job-{index + 1}",
                "backup": f"{app}-{env}-backup-{index + 1}",
                "cert": f"/etc/pki/{app}/{env}-{index + 1}.crt",
                "key": f"/etc/pki/{app}/{env}-{index + 1}.key",
                "ca": f"/etc/ssh/ca/{env}-users-{index + 1}",
                "pubkey": f"/etc/ssh/keys/{app}-{index + 1}.pub",
                "sshcert": f"/etc/ssh/keys/{app}-{index + 1}-cert.pub",
                "id": f"{index + 1:08x}",
                "uuid": f"00000000-0000-4000-8000-{index + 1:012d}",
                "ocid": f"ocid1.instance.oc1.test.{hashlib.sha256(str(index).encode()).hexdigest()[:24]}",
                "printer": f"{app}-{env}-printer-{index + 1}",
                "display": f"DP-{index + 1}",
                "camera": f"/dev/video{index}",
                "serial": f"emulator-{serial_port}",
                "module": f"{app}_{env}_{index + 1}",
                "kernel": f"6.12.{index + 1}-lab",
                "rule": f"rules/{app}-{env}-{index + 1}.yar",
                "script": f"scripts/{app}-{env}-{index + 1}.sh",
                "proto": f"proto/{app}/{env}_{index + 1}.proto",
                "model": f"{app}_{env}_model_{index + 1}",
                "task": f"{app}-{env}-task-{index + 1}",
                "entry": f"{env}/{app}/credential-{index + 1}",
            }
        )
    return contexts


CONTEXTS = build_contexts()


def add_matrix(
    category: str,
    specs: list[tuple[str, str, str]],
    contexts: list[dict[str, str | int]] | None = None,
) -> None:
    contexts = contexts or CONTEXTS
    for operation_index, (nl_template, bash_template, risk) in enumerate(specs, 1):
        if risk not in ALLOWED_RISKS:
            raise ValueError(f"Invalid risk for {category}: {risk}")
        family = f"{category}:{operation_index:02d}"
        for context in contexts:
            nl = " ".join(nl_template.format_map(context).split())
            bash = bash_template.format_map(context).strip()
            if not nl or not bash or "\n" in nl or "\n" in bash:
                raise ValueError(f"Invalid generated row in {family}")
            if re.search(r"(?:^|\s)#\s", bash):
                raise ValueError(f"Comment-only command variation in {family}: {bash}")
            if nl.casefold() in SEEN_NL or bash.casefold() in SEEN_BASH:
                continue
            SEEN_NL.add(nl.casefold())
            SEEN_BASH.add(bash.casefold())
            ROWS.append(
                {
                    "nl": nl,
                    "bash": bash,
                    "category": category,
                    "risk": risk,
                    "source": "manual-curation",
                    "family": family,
                }
            )


def add_host_and_storage_domains() -> None:
    add_matrix("network/networkmanager", [
        ("Show NetworkManager connection profile {profile}", "nmcli --fields all connection show {profile}", "safe"),
        ("Activate NetworkManager profile {profile}", "nmcli connection up {profile}", "caution"),
        ("Display NetworkManager details for interface {iface}", "nmcli --fields all device show {iface}", "safe"),
        ("Set DNS server {ip} on NetworkManager profile {profile}", "nmcli connection modify {profile} ipv4.dns {ip}", "caution"),
    ])
    add_matrix("network/firewalld", [
        ("Show all firewalld settings in zone {zone}", "firewall-cmd --zone={zone} --list-all", "safe"),
        ("Check whether TCP port {port} is open in firewalld zone {zone}", "firewall-cmd --zone={zone} --query-port={port}/tcp", "safe"),
        ("Permanently allow service {service} in firewalld zone {zone}", "firewall-cmd --permanent --zone={zone} --add-service={service}", "caution"),
        ("Remove TCP port {port} from firewalld zone {zone} permanently", "firewall-cmd --permanent --zone={zone} --remove-port={port}/tcp", "destructive"),
    ])
    add_matrix("network/ufw", [
        ("Show UFW rules related to port {port}", "ufw status numbered | grep -F -- '{port}'", "safe"),
        ("Allow {ip} to reach TCP port {port} through UFW", "ufw allow from {ip} to any port {port} proto tcp", "caution"),
        ("Delete the UFW rule allowing {ip} to TCP port {port}", "ufw delete allow from {ip} to any port {port} proto tcp", "destructive"),
        ("Show the UFW application profile for {service}", "ufw app info {service}", "safe"),
    ])
    add_matrix("network/conntrack", [
        ("List tracked TCP connections with destination port {port}", "conntrack -L -p tcp --dport {port}", "safe"),
        ("List connection-tracking entries sourced from {ip}", "conntrack -L -s {ip}", "safe"),
        ("Show conntrack events involving original destination {ip}", "conntrack -E -d {ip}", "caution"),
        ("Delete tracked connections whose original source is {ip}", "conntrack -D -s {ip}", "destructive"),
    ])
    add_matrix("network/ipset", [
        ("List the members of ipset {name}", "ipset list {name}", "safe"),
        ("Create hash-based IP set {name} if it does not exist", "ipset create {name} hash:ip -exist", "caution"),
        ("Add address {ip} to ipset {name}", "ipset add {name} {ip} -exist", "caution"),
        ("Remove address {ip} from ipset {name}", "ipset del {name} {ip}", "destructive"),
    ])
    add_matrix("devices/bluetooth", [
        ("Show Bluetooth device information for {mac}", "bluetoothctl info {mac}", "safe"),
        ("Pair with Bluetooth device {mac}", "bluetoothctl pair {mac}", "caution"),
        ("Connect to paired Bluetooth device {mac}", "bluetoothctl connect {mac}", "caution"),
        ("Disconnect Bluetooth device {mac}", "bluetoothctl disconnect {mac}", "caution"),
    ])
    add_matrix("devices/cups-printing", [
        ("Show detailed CUPS status for printer {printer}", "lpstat -p {printer} -l", "safe"),
        ("List supported options for CUPS printer {printer}", "lpoptions -p {printer} -l", "safe"),
        ("Print {file} on CUPS printer {printer}", "lp -d {printer} {file}", "caution"),
        ("Cancel print job {printer}-{i}", "cancel {printer}-{i}", "destructive"),
    ])
    add_matrix("storage/mdraid", [
        ("Show detailed status for RAID array {md}", "mdadm --detail {md}", "safe"),
        ("Examine RAID metadata on {disk}", "mdadm --examine {disk}", "safe"),
        ("Add {disk} to RAID array {md}", "mdadm --manage {md} --add {disk}", "caution"),
        ("Mark {disk} failed in RAID array {md}", "mdadm --manage {md} --fail {disk}", "destructive"),
    ])
    add_matrix("storage/luks", [
        ("Display the LUKS header on {disk}", "cryptsetup luksDump {disk}", "safe"),
        ("Print the LUKS UUID for {disk}", "cryptsetup luksUUID {disk}", "safe"),
        ("Open encrypted device {disk} as mapper {mapper}", "cryptsetup open {disk} {mapper}", "caution"),
        ("Close encrypted mapper {mapper}", "cryptsetup close {mapper}", "caution"),
    ])
    add_matrix("storage/device-mapper", [
        ("Show device-mapper information for {mapper}", "dmsetup info {mapper}", "safe"),
        ("Print the device-mapper table for {mapper}", "dmsetup table {mapper}", "safe"),
        ("Show device-mapper target status for {mapper}", "dmsetup status {mapper}", "safe"),
        ("Remove device-mapper mapping {mapper}", "dmsetup remove {mapper}", "destructive"),
    ])
    add_matrix("storage/nfs", [
        ("List NFS exports offered by {host}", "showmount --exports {host}", "safe"),
        ("Show active NFS mounts from server {host}", "nfsstat --mounts | grep -F -- '{host}'", "safe"),
        ("Mount NFS export {host}:{path} at {path}/mnt", "mount -t nfs {host}:{path} {path}/mnt", "caution"),
        ("Unmount the NFS mount at {path}/mnt", "umount {path}/mnt", "caution"),
    ])
    add_matrix("storage/samba", [
        ("List SMB shares advertised by {host} without credentials", "smbclient -L //{host} -N", "safe"),
        ("List files in SMB share {app} on {host}", "smbclient //{host}/{app} -N -c ls", "safe"),
        ("Mount SMB share {app} from {host} at {path}/smb", "mount -t cifs //{host}/{app} {path}/smb -o guest,ro", "caution"),
        ("Show Samba sessions involving share {app}", "smbstatus --shares | grep -F -- '{app}'", "safe"),
    ])
    add_matrix("storage/iscsi", [
        ("Discover iSCSI targets exposed by {host}", "iscsiadm --mode discovery --type sendtargets --portal {host}", "safe"),
        ("Log in to iSCSI target iqn.2026-01.test:{name} on {host}", "iscsiadm --mode node --targetname iqn.2026-01.test:{name} --portal {host} --login", "caution"),
        ("Log out of iSCSI target iqn.2026-01.test:{name} on {host}", "iscsiadm --mode node --targetname iqn.2026-01.test:{name} --portal {host} --logout", "caution"),
        ("Show the iSCSI session for target {name}", "iscsiadm --mode session --print 3 | grep -F -- '{name}'", "safe"),
    ])
    add_matrix("storage/ceph", [
        ("Show usage statistics for Ceph pool {pool}", "ceph osd pool stats {pool}", "safe"),
        ("List objects stored in Ceph pool {pool}", "rados --pool {pool} list", "safe"),
        ("Display information for RBD image {pool}/{name}", "rbd info {pool}/{name}", "safe"),
        ("Show disk usage for RBD image {pool}/{name}", "rbd du {pool}/{name}", "safe"),
    ])
    add_matrix("storage/gluster", [
        ("Show information for Gluster volume {volume}", "gluster volume info {volume}", "safe"),
        ("Show brick status for Gluster volume {volume}", "gluster volume status {volume} detail", "safe"),
        ("Report pending heals for Gluster volume {volume}", "gluster volume heal {volume} info", "safe"),
        ("Enable client I/O threads on Gluster volume {volume}", "gluster volume set {volume} performance.client-io-threads on", "caution"),
    ])
    add_matrix("storage/minio-client", [
        ("List objects in MinIO bucket {bucket} through alias {app}", "mc ls {app}/{bucket}", "safe"),
        ("Show MinIO metadata for {app}/{bucket}", "mc stat {app}/{bucket}", "safe"),
        ("Preview mirroring {app}/{bucket} into {path}", "mc mirror --dry-run {app}/{bucket} {path}", "safe"),
        ("Show MinIO server information for alias {app}", "mc admin info {app}", "safe"),
    ])


def add_package_and_host_admin_domains() -> None:
    add_matrix("packages/apt", [
        ("Show installed and candidate APT versions for {pkg}", "apt-cache policy {pkg}", "safe"),
        ("Display APT package metadata for {pkg}", "apt-cache show {pkg}", "safe"),
        ("Simulate installing APT package {pkg}", "apt-get install --simulate {pkg}", "safe"),
        ("List files installed by Debian package {pkg}", "dpkg-query --listfiles {pkg}", "safe"),
    ])
    add_matrix("packages/dnf", [
        ("Show DNF package information for {pkg}", "dnf info {pkg}", "safe"),
        ("List packages that require {pkg} using DNF repoquery", "dnf repoquery --whatrequires {pkg}", "safe"),
        ("Preview installing {pkg} with DNF without confirming", "dnf install --assumeno {pkg}", "safe"),
        ("List files supplied by DNF package {pkg}", "dnf repoquery --list {pkg}", "safe"),
    ])
    add_matrix("packages/pacman", [
        ("Show Arch repository information for {pkg}", "pacman --sync --info {pkg}", "safe"),
        ("List files owned by installed Arch package {pkg}", "pacman --query --list {pkg}", "safe"),
        ("Print the dependency tree for Arch package {pkg}", "pactree {pkg}", "safe"),
        ("Print packages Pacman would download for {pkg}", "pacman --sync --print {pkg}", "safe"),
    ])
    add_matrix("packages/zypper", [
        ("Show Zypper package details for {pkg}", "zypper --non-interactive info {pkg}", "safe"),
        ("Search enabled Zypper repositories for {pkg}", "zypper --non-interactive search --details {pkg}", "safe"),
        ("Find which Zypper package provides {pkg}", "zypper --non-interactive what-provides {pkg}", "safe"),
        ("Dry-run installing {pkg} with Zypper", "zypper --non-interactive install --dry-run {pkg}", "safe"),
    ])
    add_matrix("packages/nix", [
        ("Search nixpkgs for {pkg}", "nix search nixpkgs {pkg}", "safe"),
        ("Show the Nix derivation path for nixpkgs package {pkg}", "nix path-info --derivation nixpkgs#{pkg}", "safe"),
        ("Preview building nixpkgs package {pkg}", "nix build --dry-run nixpkgs#{pkg}", "safe"),
        ("Show closure size for nixpkgs package {pkg}", "nix path-info --closure-size nixpkgs#{pkg}", "safe"),
    ])
    add_matrix("packages/flatpak", [
        ("Show Flatpak information for application test.{app}.{i}", "flatpak info test.{app}.{i}", "safe"),
        ("Show Flathub metadata for Flatpak test.{app}.{i}", "flatpak remote-info flathub test.{app}.{i}", "safe"),
        ("Display sandbox permissions for Flatpak test.{app}.{i}", "flatpak info --show-permissions test.{app}.{i}", "safe"),
        ("Install Flatpak test.{app}.{i} from Flathub", "flatpak install --noninteractive flathub test.{app}.{i}", "caution"),
    ])
    add_matrix("packages/snap", [
        ("Show Snap metadata for {pkg}", "snap info {pkg}", "safe"),
        ("List interface connections for Snap {pkg}", "snap connections {pkg}", "safe"),
        ("Show services declared by Snap {pkg}", "snap services {pkg}", "safe"),
        ("Download Snap {pkg} without installing it", "snap download {pkg}", "caution"),
    ])
    add_matrix("system/boot-inspection", [
        ("Show grubby information for kernel /boot/vmlinuz-{kernel}", "grubby --info=/boot/vmlinuz-{kernel}", "safe"),
        ("Find EFI boot entries mentioning {name}", "efibootmgr --verbose | grep -F -- '{name}'", "safe"),
        ("Test whether machine-owner key {cert} is enrolled", "mokutil --test-key {cert}", "safe"),
        ("Show kernel command-line entries mentioning {module}", "grubby --info=ALL | grep -F -- '{module}'", "safe"),
    ])
    add_matrix("system/initramfs", [
        ("Inspect initramfs /boot/initramfs-{kernel}.img for module {module}", "lsinitrd /boot/initramfs-{kernel}.img | grep -F -- '{module}'", "safe"),
        ("List dracut modules matching {module}", "dracut --list-modules | grep -F -- '{module}'", "safe"),
        ("Extract /boot/initrd.img-{kernel} into {path}/initramfs", "unmkinitramfs /boot/initrd.img-{kernel} {path}/initramfs", "caution"),
        ("Update the initramfs for kernel {kernel}", "update-initramfs -u -k {kernel}", "caution"),
    ])
    add_matrix("system/loginctl", [
        ("Show logind properties for user {user}", "loginctl show-user {user} --all", "safe"),
        ("List login sessions belonging to {user}", "loginctl list-sessions --no-legend | grep -F -- '{user}'", "safe"),
        ("Enable lingering user services for {user}", "loginctl enable-linger {user}", "caution"),
        ("Terminate every login session for {user}", "loginctl terminate-user {user}", "destructive"),
    ])
    add_matrix("system/dbus", [
        ("Show D-Bus service status for test.{app}.{i}", "busctl status test.{app}.{i}", "safe"),
        ("Introspect D-Bus object /test/{app}/{i} from test.{app}.{i}", "busctl introspect test.{app}.{i} /test/{app}/{i}", "safe"),
        ("Show the D-Bus process credentials for test.{app}.{i}", "busctl --augment-creds status test.{app}.{i}", "safe"),
        ("Print the D-Bus object tree exported by test.{app}.{i}", "busctl tree test.{app}.{i}", "safe"),
    ])
    add_matrix("system/logrotate", [
        ("Debug logrotate configuration {config} without rotating files", "logrotate --debug {config}", "safe"),
        ("Show verbose logrotate decisions for {config}", "logrotate --verbose --debug {config}", "safe"),
        ("Debug {config} with isolated state file {path}/logrotate.state", "logrotate --debug --state {path}/logrotate.state {config}", "safe"),
        ("Force the rotations configured by {config}", "logrotate --force {config}", "caution"),
    ])


def add_security_and_messaging_domains() -> None:
    add_matrix("security/fail2ban", [
        ("Show Fail2ban status for jail {name}", "fail2ban-client status {name}", "safe"),
        ("List addresses banned by Fail2ban jail {name}", "fail2ban-client get {name} banip", "safe"),
        ("Unban address {ip} from Fail2ban jail {name}", "fail2ban-client set {name} unbanip {ip}", "caution"),
        ("Ban address {ip} in Fail2ban jail {name}", "fail2ban-client set {name} banip {ip}", "caution"),
    ])
    add_matrix("security/clamav", [
        ("Scan {file} with ClamAV and print infected files only", "clamscan --infected --no-summary {file}", "safe"),
        ("Recursively scan {path} with ClamAV without removing anything", "clamscan --recursive --infected {path}", "safe"),
        ("Scan {file} through the ClamAV daemon", "clamdscan --fdpass {file}", "safe"),
        ("Show metadata for the ClamAV signature database at {path}/clamav/daily.cvd", "sigtool --info {path}/clamav/daily.cvd", "safe"),
    ])
    add_matrix("security/yara", [
        ("Scan {file} with YARA rule file {rule}", "yara {rule} {file}", "safe"),
        ("Recursively scan {path} with YARA rules {rule}", "yara --recursive {rule} {path}", "safe"),
        ("Print YARA match metadata while scanning {file} with {rule}", "yara --print-meta {rule} {file}", "safe"),
        ("Compile YARA source {rule} into {path}/{name}.yarac", "yarac {rule} {path}/{name}.yarac", "caution"),
    ])
    add_matrix("security/osquery", [
        ("Use osquery to show the process named {app}", "osqueryi --json \"SELECT pid,name,path FROM processes WHERE name='{app}';\"", "safe"),
        ("Use osquery to list listening sockets on port {port}", "osqueryi --json \"SELECT pid,port,address FROM listening_ports WHERE port={port};\"", "safe"),
        ("Use osquery to find Debian package records matching {pkg}", "osqueryi --json \"SELECT name,version FROM deb_packages WHERE name='{pkg}';\"", "safe"),
        ("Use osquery to inspect user {user}", "osqueryi --json \"SELECT username,uid,gid,directory FROM users WHERE username='{user}';\"", "safe"),
    ])
    add_matrix("security/semgrep", [
        ("Scan repository {repo} with Semgrep security-audit rules", "semgrep scan --config p/security-audit {repo}", "safe"),
        ("Run Semgrep auto rules on {repo} and emit JSON", "semgrep scan --config auto --json {repo}", "safe"),
        ("Scan files matching {name}* under {repo} with Semgrep default rules", "semgrep scan --config p/default --include '{name}*' {repo}", "safe"),
        ("Run Semgrep secrets rules against {repo}", "semgrep scan --config p/secrets {repo}", "safe"),
    ])
    add_matrix("security/certbot", [
        ("Show Certbot certificate records for {domain}", "certbot certificates | grep -F -- '{domain}'", "safe"),
        ("Dry-run renewal of the Certbot certificate named {domain}", "certbot renew --cert-name {domain} --dry-run", "safe"),
        ("Show the Certbot renewal configuration for {domain}", "certbot certificates --cert-name {domain}", "safe"),
        ("Dry-run webroot renewal of the Certbot certificate named {domain}", "certbot renew --cert-name {domain} --dry-run --webroot --webroot-path {path}", "safe"),
    ])
    add_matrix("security/ssh-certificates", [
        ("Inspect SSH certificate {sshcert}", "ssh-keygen -Lf {sshcert}", "safe"),
        ("Sign {pubkey} for SSH principal {user} using CA {ca}", "ssh-keygen -s {ca} -I {name} -n {user} {pubkey}", "caution"),
        ("Create SSH key-revocation list {path}/{name}.krl containing {sshcert}", "ssh-keygen -k -f {path}/{name}.krl {sshcert}", "caution"),
        ("Check whether {sshcert} appears in SSH KRL {path}/{name}.krl", "ssh-keygen -Q -f {path}/{name}.krl {sshcert}", "safe"),
    ])
    add_matrix("messaging/rabbitmq", [
        ("Show RabbitMQ queue {queue} in virtual host {vhost}", "rabbitmqctl list_queues --vhost {vhost} name messages consumers | grep -F -- '{queue}'", "safe"),
        ("List RabbitMQ bindings in virtual host {vhost} involving {app}", "rabbitmqctl list_bindings --vhost {vhost} source_name destination_name | grep -F -- '{app}'", "safe"),
        ("List RabbitMQ consumers in virtual host {vhost} for queue {queue}", "rabbitmqctl list_consumers --vhost {vhost} queue_name consumer_tag | grep -F -- '{queue}'", "safe"),
        ("Purge every message from RabbitMQ queue {queue} in {vhost}", "rabbitmqctl purge_queue --vhost {vhost} {queue}", "destructive"),
    ])
    add_matrix("messaging/nats", [
        ("Show NATS JetStream stream {stream}", "nats stream info {stream}", "safe"),
        ("Show NATS consumer {consumer} on stream {stream}", "nats consumer info {stream} {consumer}", "safe"),
        ("List messages in NATS stream {stream} without acknowledging them", "nats stream view {stream} --count 1", "safe"),
        ("Purge all messages from NATS stream {stream}", "nats stream purge {stream} --force", "destructive"),
    ])
    add_matrix("messaging/mqtt", [
        ("Read one MQTT message from topic {topic} on {host}:{port}", "mosquitto_sub -h {host} -p {port} -t {topic} -C 1", "safe"),
        ("Publish a test message to MQTT topic {topic} on {host}:{port}", "mosquitto_pub -h {host} -p {port} -t {topic} -m 'test-{id}'", "caution"),
        ("Request one MQTT response on {topic}/reply through {host}", "mosquitto_rr -h {host} -p {port} -t {topic}/request -e {topic}/reply -m 'probe-{id}'", "caution"),
        ("Clear the retained MQTT message on topic {topic}", "mosquitto_pub -h {host} -p {port} -t {topic} -n -r", "destructive"),
    ])
    add_matrix("messaging/pulsar", [
        ("Show statistics for Pulsar topic persistent://{env}/{app}/{topic}", "pulsar-admin topics stats persistent://{env}/{app}/{topic}", "safe"),
        ("List subscriptions on Pulsar topic persistent://{env}/{app}/{topic}", "pulsar-admin topics subscriptions persistent://{env}/{app}/{topic}", "safe"),
        ("Peek one message from Pulsar subscription {consumer} on {topic}", "pulsar-admin topics peek-messages --subscription {consumer} --count 1 persistent://{env}/{app}/{topic}", "safe"),
        ("Unload Pulsar topic persistent://{env}/{app}/{topic}", "pulsar-admin topics unload persistent://{env}/{app}/{topic}", "caution"),
    ])
    add_matrix("messaging/redpanda", [
        ("Describe Redpanda topic {topic}", "rpk topic describe {topic}", "safe"),
        ("Consume one record from Redpanda topic {topic}", "rpk topic consume {topic} --num 1", "safe"),
        ("Describe Redpanda consumer group {group}", "rpk group describe {group}", "safe"),
        ("Delete Redpanda topic {topic}", "rpk topic delete {topic}", "destructive"),
    ])


def add_orchestration_domains() -> None:
    add_matrix("orchestration/nomad", [
        ("Show status for Nomad job {job}", "nomad job status {job}", "safe"),
        ("Inspect the full Nomad job definition for {job}", "nomad job inspect {job}", "safe"),
        ("Show Nomad allocation {uuid}", "nomad alloc status {uuid}", "safe"),
        ("Stop and purge Nomad job {job}", "nomad job stop -purge {job}", "destructive"),
    ])
    add_matrix("orchestration/consul", [
        ("List Consul catalog nodes providing service {service}", "consul catalog nodes -service {service}", "safe"),
        ("Show detailed Consul catalog nodes for service {service}", "consul catalog nodes -service {service} -detailed", "safe"),
        ("Read Consul KV entry {env}/{app}/{name}", "consul kv get {env}/{app}/{name}", "safe"),
        ("Delete Consul KV entry {env}/{app}/{name}", "consul kv delete {env}/{app}/{name}", "destructive"),
    ])
    add_matrix("iac/packer", [
        ("Initialize Packer template {repo}/{name}.pkr.hcl", "packer init {repo}/{name}.pkr.hcl", "caution"),
        ("Validate Packer template {repo}/{name}.pkr.hcl", "packer validate {repo}/{name}.pkr.hcl", "safe"),
        ("Check formatting of Packer template {repo}/{name}.pkr.hcl", "packer fmt -check {repo}/{name}.pkr.hcl", "safe"),
        ("Inspect the components in Packer template {repo}/{name}.pkr.hcl", "packer inspect {repo}/{name}.pkr.hcl", "safe"),
    ])
    add_matrix("gitops/argocd", [
        ("Show Argo CD application {name}", "argocd app get {name}", "safe"),
        ("Show deployment history for Argo CD application {name}", "argocd app history {name}", "safe"),
        ("Display pending differences for Argo CD application {name}", "argocd app diff {name}", "safe"),
        ("Synchronize Argo CD application {name}", "argocd app sync {name}", "caution"),
    ])
    add_matrix("gitops/flux", [
        ("Show Flux kustomization {name} in namespace {namespace}", "flux get kustomization {name} --namespace {namespace}", "safe"),
        ("Diff Flux kustomization {name} against {repo}", "flux diff kustomization {name} --path {repo}", "safe"),
        ("Suspend Flux kustomization {name} in {namespace}", "flux suspend kustomization {name} --namespace {namespace}", "caution"),
        ("Resume Flux kustomization {name} in {namespace}", "flux resume kustomization {name} --namespace {namespace}", "caution"),
    ])
    add_matrix("kubernetes/kustomize-cli", [
        ("Render Kustomize overlay {repo}/overlays/{env}", "kustomize build {repo}/overlays/{env}", "safe"),
        ("Render Kustomize overlay {repo}/overlays/{env} with Helm enabled", "kustomize build --enable-helm {repo}/overlays/{env}", "safe"),
        ("Render {repo} while allowing Kustomize files outside its root", "kustomize build {repo} --load-restrictor LoadRestrictionsNone", "safe"),
        ("Set image {app} to {image} in Kustomize directory {repo}", "cd {repo} && kustomize edit set image {app}={image}", "caution"),
    ])
    add_matrix("kubernetes/kind", [
        ("Print kubeconfig for kind cluster {cluster}", "kind get kubeconfig --name {cluster}", "safe"),
        ("Export diagnostic logs from kind cluster {cluster} to {path}/kind-logs", "kind export logs {path}/kind-logs --name {cluster}", "caution"),
        ("Load container image {image} into kind cluster {cluster}", "kind load docker-image {image} --name {cluster}", "caution"),
        ("Delete kind cluster {cluster}", "kind delete cluster --name {cluster}", "destructive"),
    ])
    add_matrix("kubernetes/minikube", [
        ("Show status for minikube profile {profile}", "minikube status --profile {profile}", "safe"),
        ("Print the IP address for minikube profile {profile}", "minikube ip --profile {profile}", "safe"),
        ("List addons for minikube profile {profile}", "minikube addons list --profile {profile}", "safe"),
        ("Stop minikube profile {profile}", "minikube stop --profile {profile}", "caution"),
    ])
    add_matrix("containers/crictl", [
        ("Inspect CRI container {id}", "crictl inspect {id}", "safe"),
        ("Show the last 100 CRI log lines for container {id}", "crictl logs --tail=100 {id}", "safe"),
        ("Show one resource-usage sample for CRI container {id}", "crictl stats {id}", "safe"),
        ("Stop CRI container {id} with a 30-second timeout", "crictl stop --timeout 30 {id}", "caution"),
    ])
    add_matrix("containers/nerdctl", [
        ("Inspect nerdctl container {name}", "nerdctl inspect {name}", "safe"),
        ("Show the last 100 nerdctl logs for {name}", "nerdctl logs --tail 100 {name}", "safe"),
        ("Show one nerdctl resource-usage sample for {name}", "nerdctl stats --no-stream {name}", "safe"),
        ("Remove nerdctl container {name}", "nerdctl rm {name}", "destructive"),
    ])
    add_matrix("kubernetes/velero", [
        ("Describe Velero backup {backup} with details", "velero backup describe {backup} --details", "safe"),
        ("Show logs for Velero backup {backup}", "velero backup logs {backup}", "safe"),
        ("Create Velero restore {name} from backup {backup}", "velero restore create {name} --from-backup {backup}", "caution"),
        ("Delete Velero backup {backup} and its object data", "velero backup delete {backup} --confirm", "destructive"),
    ])


def add_data_and_development_domains() -> None:
    add_matrix("databases/mongodb", [
        ("List collections in MongoDB database {database} on {host}", "mongosh mongodb://{host}:{port}/{database} --quiet --eval 'db.getCollectionNames()'", "safe"),
        ("Show MongoDB database statistics for {database} on {host}", "mongosh mongodb://{host}:{port}/{database} --quiet --eval 'db.stats()'", "safe"),
        ("Count documents in MongoDB collection {table} in {database}", "mongosh mongodb://{host}:{port}/{database} --quiet --eval 'db.{table}.countDocuments()'", "safe"),
        ("Explain a MongoDB lookup of identifier {id} in {table}", "mongosh mongodb://{host}:{port}/{database} --quiet --eval 'db.{table}.find({{_id:\"{id}\"}}).explain()'", "safe"),
    ])
    add_matrix("databases/clickhouse", [
        ("List tables in ClickHouse database {database} on {host}", "clickhouse-client --host {host} --port {port} --database {database} --query 'SHOW TABLES'", "safe"),
        ("Describe ClickHouse table {database}.{table}", "clickhouse-client --host {host} --port {port} --query 'DESCRIBE TABLE {database}.{table}'", "safe"),
        ("Count rows in ClickHouse table {database}.{table}", "clickhouse-client --host {host} --port {port} --query 'SELECT count() FROM {database}.{table}'", "safe"),
        ("Explain a ClickHouse scan of {database}.{table}", "clickhouse-client --host {host} --port {port} --query 'EXPLAIN SELECT * FROM {database}.{table} LIMIT 10'", "safe"),
    ])
    add_matrix("databases/opensearch", [
        ("Show OpenSearch index metadata for {name} on {host}", "curl --fail --silent 'https://{host}:{port}/{name}'", "safe"),
        ("Count documents in OpenSearch index {name} on {host}", "curl --fail --silent 'https://{host}:{port}/{name}/_count'", "safe"),
        ("Show the field mapping for OpenSearch index {name}", "curl --fail --silent 'https://{host}:{port}/{name}/_mapping'", "safe"),
        ("Explain an OpenSearch match-all query against {name}", "curl --fail --silent --header 'Content-Type: application/json' --request POST --data '{{\"query\":{{\"match_all\":{{}}}}}}' 'https://{host}:{port}/{name}/_validate/query?explain=true'", "safe"),
    ])
    add_matrix("databases/influxdb", [
        ("Show InfluxDB bucket {bucket}", "influx bucket list --name {bucket}", "safe"),
        ("Query the latest record from InfluxDB bucket {bucket}", "influx query 'from(bucket: \"{bucket}\") |> range(start: -1h) |> limit(n: 1)'", "safe"),
        ("List up to {i} InfluxDB tasks", "influx task list --limit {i}", "safe"),
        ("Delete InfluxDB bucket {bucket}", "influx bucket delete --name {bucket}", "destructive"),
    ])
    add_matrix("databases/trino", [
        ("List tables in Trino schema hive.{database} on {host}", "trino --server https://{host}:{port} --catalog hive --schema {database} --execute 'SHOW TABLES'", "safe"),
        ("Describe Trino table hive.{database}.{table}", "trino --server https://{host}:{port} --execute 'DESCRIBE hive.{database}.{table}'", "safe"),
        ("Count rows in Trino table hive.{database}.{table}", "trino --server https://{host}:{port} --execute 'SELECT count(*) FROM hive.{database}.{table}'", "safe"),
        ("Explain a Trino scan of hive.{database}.{table}", "trino --server https://{host}:{port} --execute 'EXPLAIN SELECT * FROM hive.{database}.{table} LIMIT 10'", "safe"),
    ])
    add_matrix("data/dbt", [
        ("List dbt model {model} in project {repo}", "dbt ls --project-dir {repo} --select {model}", "safe"),
        ("Compile dbt model {model} in project {repo}", "dbt compile --project-dir {repo} --select {model}", "caution"),
        ("Test dbt model {model} in project {repo}", "dbt test --project-dir {repo} --select {model}", "safe"),
        ("Generate dbt documentation artifacts for project {repo}", "dbt docs generate --project-dir {repo}", "caution"),
    ])
    add_matrix("data/spark-sql", [
        ("List tables in Spark SQL database {database}", "spark-sql --database {database} --execute 'SHOW TABLES'", "safe"),
        ("Describe Spark SQL table {database}.{table}", "spark-sql --database {database} --execute 'DESCRIBE EXTENDED {table}'", "safe"),
        ("Count rows in Spark SQL table {database}.{table}", "spark-sql --database {database} --execute 'SELECT count(*) FROM {table}'", "safe"),
        ("Explain a Spark SQL scan of {database}.{table}", "spark-sql --database {database} --execute 'EXPLAIN SELECT * FROM {table} LIMIT 10'", "safe"),
    ])
    add_matrix("data/hdfs", [
        ("List HDFS directory {path}", "hdfs dfs -ls {path}", "safe"),
        ("Show HDFS disk usage under {path}", "hdfs dfs -du -h {path}", "safe"),
        ("Count directories, files, and bytes under HDFS path {path}", "hdfs dfs -count -q -h {path}", "safe"),
        ("Print the HDFS checksum for {file}", "hdfs dfs -checksum {file}", "safe"),
    ])
    add_matrix("languages/ruby", [
        ("Check whether bundled Ruby dependencies are satisfied in {repo}", "bundle check --gemfile={repo}/Gemfile", "safe"),
        ("Syntax-check Ruby file {repo}/lib/{app}_{i}.rb", "ruby -c {repo}/lib/{app}_{i}.rb", "safe"),
        ("Show Ruby gem dependencies for {pkg}", "gem dependency {pkg} --reverse-dependencies", "safe"),
        ("Check whether Ruby gem {pkg} is outdated in {repo}", "bundle outdated {pkg} --gemfile={repo}/Gemfile --strict", "safe"),
    ])
    add_matrix("languages/php", [
        ("Show Composer package {pkg} in project {repo}", "composer show --working-dir={repo} {pkg}", "safe"),
        ("Audit Composer dependencies in {repo}", "composer audit --working-dir={repo} --locked", "safe"),
        ("Syntax-check PHP file {repo}/src/{app}_{i}.php", "php -l {repo}/src/{app}_{i}.php", "safe"),
        ("List outdated Composer package {pkg} in {repo}", "composer outdated --working-dir={repo} {pkg} --direct", "safe"),
    ])
    add_matrix("languages/elixir", [
        ("Show the Mix dependency tree for project {repo}", "cd {repo} && mix deps.tree", "safe"),
        ("Compile Elixir project {repo} while treating warnings as errors", "cd {repo} && mix compile --warnings-as-errors", "caution"),
        ("Run Elixir test file {repo}/test/{app}_{i}_test.exs", "cd {repo} && mix test test/{app}_{i}_test.exs", "safe"),
        ("Show outdated Hex dependencies in project {repo}", "cd {repo} && mix hex.outdated", "safe"),
    ])
    add_matrix("languages/haskell", [
        ("Type-check Haskell source {repo}/src/{app}_{i}.hs without generating code", "ghc -fno-code {repo}/src/{app}_{i}.hs", "safe"),
        ("Show the Stack dependency tree for Haskell project {repo}", "cd {repo} && stack ls dependencies", "safe"),
        ("Build Haskell tests in {repo} without running them", "cd {repo} && stack test --no-run-tests", "caution"),
        ("Show installed Cabal packages matching {pkg}", "cabal list --installed {pkg}", "safe"),
    ])
    add_matrix("languages/swift", [
        ("Describe the Swift package at {repo}", "swift package --package-path {repo} describe", "safe"),
        ("Show dependencies of the Swift package at {repo}", "swift package --package-path {repo} show-dependencies", "safe"),
        ("Resolve dependencies for the Swift package at {repo}", "swift package --package-path {repo} resolve", "caution"),
        ("Run Swift tests matching {app}_{i} in {repo}", "swift test --package-path {repo} --filter {app}_{i}", "safe"),
    ])
    add_matrix("languages/julia", [
        ("Show Julia package status for project {repo}", "julia --project={repo} -e 'using Pkg; Pkg.status()'", "safe"),
        ("Show outdated Julia packages in project {repo}", "julia --project={repo} -e 'using Pkg; Pkg.status(; outdated=true)'", "safe"),
        ("Run Julia test file {repo}/test/{app}_{i}.jl", "julia --project={repo} {repo}/test/{app}_{i}.jl", "safe"),
        ("Precompile the Julia environment in {repo}", "julia --project={repo} -e 'using Pkg; Pkg.precompile()'", "caution"),
    ])
    add_matrix("languages/r", [
        ("Show the installed R version of package {pkg}", "Rscript -e 'packageVersion(\"{pkg}\")'", "safe"),
        ("Run R script {repo}/scripts/{app}_{i}.R with argument {env}", "Rscript {repo}/scripts/{app}_{i}.R {env}", "safe"),
        ("Check R package source directory {repo}", "R CMD check --no-manual {repo}", "caution"),
        ("List files installed by R package {pkg}", "Rscript -e 'system.file(package=\"{pkg}\") |> list.files(recursive=TRUE)'", "safe"),
    ])
    add_matrix("languages/lua", [
        ("Show LuaRocks metadata for {pkg}", "luarocks show {pkg}", "safe"),
        ("Find installed Lua rock {pkg}", "luarocks list --porcelain | grep -F -- '{pkg}'", "safe"),
        ("Syntax-check Lua file {repo}/{app}_{i}.lua", "luac -p {repo}/{app}_{i}.lua", "safe"),
        ("Show dependencies of Lua rock {pkg}", "luarocks show {pkg} | sed -n '/Dependencies:/,/^$/p'", "safe"),
    ])
    add_matrix("git/git-lfs", [
        ("List Git LFS files in repository {repo}", "git -C {repo} lfs ls-files", "safe"),
        ("Show Git LFS status in repository {repo}", "git -C {repo} lfs status", "safe"),
        ("Report large-file migration candidates in {repo}", "git -C {repo} lfs migrate info --include='*.{id}'", "safe"),
        ("Verify Git LFS objects in repository {repo}", "git -C {repo} lfs fsck", "safe"),
    ])
    add_matrix("git/git-annex", [
        ("Show git-annex status in repository {repo}", "git -C {repo} annex status", "safe"),
        ("Show repositories containing annexed file artifacts/{name}.json", "git -C {repo} annex whereis artifacts/{name}.json", "safe"),
        ("List annexed files under artifacts/{name} that are not present locally", "git -C {repo} annex find artifacts/{name} --not --in here", "safe"),
        ("Run a fast git-annex integrity check on artifacts/{name}.json", "git -C {repo} annex fsck --fast artifacts/{name}.json", "safe"),
    ])
    add_matrix("development/protobuf", [
        ("Compile descriptor set for Protocol Buffer file {proto}", "protoc --include_imports --descriptor_set_out={path}/{name}.pb {proto}", "caution"),
        ("Lint the Buf module in {repo}", "buf lint {repo}", "safe"),
        ("Show formatting differences for Protocol Buffers in {repo}", "buf format --diff {repo}", "safe"),
        ("Check {repo} for breaking Protobuf changes against its main branch", "cd {repo} && buf breaking --against '.git#branch=main'", "safe"),
    ])
    add_matrix("development/shell-lint", [
        ("Run ShellCheck with sourced-file following on {script}", "shellcheck --external-sources {script}", "safe"),
        ("Show shfmt formatting differences for {script}", "shfmt --diff {script}", "safe"),
        ("Syntax-check {script} with Bash", "bash -n {script}", "safe"),
        ("Syntax-check {script} with Dash", "dash -n {script}", "safe"),
    ])
    add_matrix("development/documentation", [
        ("Build strict Sphinx HTML documentation from {repo}/docs", "sphinx-build -nW -b html {repo}/docs {path}/sphinx-html", "caution"),
        ("Build MkDocs site {repo}/mkdocs.yml in strict mode", "mkdocs build --strict --config-file {repo}/mkdocs.yml --site-dir {path}/mkdocs-site", "caution"),
        ("Run Python doctests in {repo}/docs/{app}_{i}.rst", "python -m doctest {repo}/docs/{app}_{i}.rst", "safe"),
        ("Lint prose in {repo}/docs with Vale", "vale {repo}/docs", "safe"),
    ])
    add_matrix("development/graphviz", [
        ("Render Graphviz file {repo}/{name}.dot as SVG", "dot -Tsvg {repo}/{name}.dot -o {path}/{name}.svg", "caution"),
        ("Print Graphviz plain layout for {repo}/{name}.dot", "dot -Tplain {repo}/{name}.dot", "safe"),
        ("Render large Graphviz graph {repo}/{name}.dot with sfdp", "sfdp -Tpng {repo}/{name}.dot -o {path}/{name}.png", "caution"),
        ("Check whether Graphviz graph {repo}/{name}.dot is acyclic", "acyclic -v {repo}/{name}.dot", "safe"),
    ])
    add_matrix("virtualization/vagrant", [
        ("Show Vagrant machine {name} status in {repo}", "cd {repo} && vagrant status {name}", "safe"),
        ("Print SSH configuration for Vagrant machine {name} in {repo}", "cd {repo} && vagrant ssh-config {name}", "safe"),
        ("Validate the Vagrantfile in {repo}", "cd {repo} && vagrant validate", "safe"),
        ("Halt Vagrant machine {name} in {repo}", "cd {repo} && vagrant halt {name}", "caution"),
    ])
    add_matrix("virtualization/machinectl", [
        ("Show machinectl status for container {name}", "machinectl status {name}", "safe"),
        ("Show all machinectl properties for {name}", "machinectl show {name} --all", "safe"),
        ("Copy {file} into machine {name} at /tmp/manifest.json", "machinectl copy-to {name} {file} /tmp/manifest.json", "caution"),
        ("Terminate systemd machine {name}", "machinectl terminate {name}", "destructive"),
    ])


def main() -> None:
    add_host_and_storage_domains()
    add_package_and_host_admin_domains()
    add_security_and_messaging_domains()
    add_orchestration_domains()
    add_data_and_development_domains()
    validate_and_write()


def validate_and_write() -> None:
    required = {"nl", "bash", "category", "risk", "source", "family"}
    for index, row in enumerate(ROWS):
        if set(row) != required:
            raise ValueError(f"Row {index} has invalid schema")
        if any(not value.strip() for value in row.values()):
            raise ValueError(f"Row {index} contains an empty value")
        if row["risk"] not in ALLOWED_RISKS or row["source"] != "manual-curation":
            raise ValueError(f"Row {index} has invalid provenance or risk")
        if "\n" in row["nl"] or "\n" in row["bash"]:
            raise ValueError(f"Row {index} is multiline")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(ROWS, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(ROWS):,} rows to {OUTPUT}")
    print(f"categories={len(set(row['category'] for row in ROWS))}")
    print(f"families={len(set(row['family'] for row in ROWS))}")
    print(f"risk={dict(Counter(row['risk'] for row in ROWS))}")


if __name__ == "__main__":
    main()
