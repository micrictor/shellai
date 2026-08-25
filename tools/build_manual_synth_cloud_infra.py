#!/usr/bin/env python3
"""Build a manually curated, deterministic cloud/infra NL-to-Bash dataset shard.

Every command family and its language realization is deliberately authored here.
Expansion is limited to realistic resource names, regions, namespaces, and flags;
no external model or generative service is used.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "manual_synth_cloud_infra.json"
ROWS: list[dict[str, str]] = []
SEEN_NL: set[str] = set()
SEEN_BASH: set[str] = set()
RISKS = {"safe", "caution", "destructive"}


def q(value: str) -> str:
    return shlex.quote(value)


def add(nl: str, bash: str, category: str, risk: str = "safe") -> None:
    nl = " ".join(nl.split())
    bash = bash.strip()
    assert nl and bash and category
    assert risk in RISKS
    assert "\n" not in bash and "\r" not in bash
    # Require independently useful examples rather than duplicate paraphrases.
    if nl in SEEN_NL or bash in SEEN_BASH:
        return
    SEEN_NL.add(nl)
    SEEN_BASH.add(bash)
    command_head = " ".join(bash.split()[:2])
    ROWS.append(
        {
            "nl": nl,
            "bash": bash,
            "category": category,
            "risk": risk,
            "source": "manual-curation",
            "family": f"{category}::{command_head}",
        }
    )


def kubernetes() -> None:
    namespaces = ["default", "staging", "production", "payments", "observability", "platform", "edge", "data", "security", "ml", "batch", "sandbox"]
    objects = [
        ("deployment", "api"), ("deployment", "web"), ("deployment", "worker"),
        ("statefulset", "postgres"), ("statefulset", "redis"), ("daemonset", "node-agent"),
        ("service", "api"), ("service", "frontend"), ("configmap", "app-config"),
        ("secret", "app-secrets"), ("job", "db-migrate"), ("cronjob", "nightly-backup"),
        ("ingress", "public-ingress"), ("networkpolicy", "deny-by-default"),
        ("serviceaccount", "workload"), ("persistentvolumeclaim", "app-data"),
    ]
    for ns in namespaces:
        for kind, name in objects:
            add(f"Get the {name} {kind} in the {ns} namespace", f"kubectl get {kind} {q(name)} -n {q(ns)}", f"kubernetes/{kind}")
            add(f"Describe the {name} {kind} in namespace {ns}", f"kubectl describe {kind} {q(name)} -n {q(ns)}", f"kubernetes/{kind}")
            add(f"Print the YAML for the {name} {kind} in {ns}", f"kubectl get {kind} {q(name)} -n {q(ns)} -o yaml", f"kubernetes/{kind}")
    resources = ["pods", "deployments", "statefulsets", "daemonsets", "services", "ingresses", "jobs", "cronjobs", "configmaps", "secrets", "networkpolicies", "persistentvolumeclaims"]
    for ns in namespaces:
        for resource in resources:
            add(f"List all {resource} in the {ns} namespace", f"kubectl get {resource} -n {q(ns)}", f"kubernetes/{resource}")
            add(f"List {resource} with extra details in namespace {ns}", f"kubectl get {resource} -n {q(ns)} -o wide", f"kubernetes/{resource}")
            add(f"Show the names only for {resource} in {ns}", f"kubectl get {resource} -n {q(ns)} -o name", f"kubernetes/{resource}")
    apps = ["api", "web", "worker", "billing", "catalog", "gateway", "auth", "notifications", "search", "reporting", "scheduler", "ingester"]
    for ns in namespaces:
        for app in apps:
            add(f"Show logs from the {app} application in {ns}", f"kubectl logs -n {q(ns)} -l {q('app=' + app)} --tail=200", "kubernetes/logs")
            add(f"Follow logs from all {app} containers in namespace {ns}", f"kubectl logs -n {q(ns)} -l {q('app=' + app)} --all-containers=true -f", "kubernetes/logs")
            add(f"List pods for the {app} application in {ns}", f"kubectl get pods -n {q(ns)} -l {q('app=' + app)}", "kubernetes/pods")
            add(f"Restart the {app} deployment in {ns}", f"kubectl rollout restart deployment/{q(app)} -n {q(ns)}", "kubernetes/rollout", "caution")
            add(f"Check rollout status for the {app} deployment in {ns}", f"kubectl rollout status deployment/{q(app)} -n {q(ns)} --timeout=5m", "kubernetes/rollout")
            add(f"Show revision history for the {app} deployment in {ns}", f"kubectl rollout history deployment/{q(app)} -n {q(ns)}", "kubernetes/rollout")
            add(f"Undo the latest rollout of {app} in {ns}", f"kubectl rollout undo deployment/{q(app)} -n {q(ns)}", "kubernetes/rollout", "caution")
            replicas = 2 + (len(app) % 5)
            add(f"Scale the {app} deployment in {ns} to {replicas} replicas", f"kubectl scale deployment/{q(app)} -n {q(ns)} --replicas={replicas}", "kubernetes/scaling", "caution")
            add(f"Wait for the {app} deployment in {ns} to become available", f"kubectl wait -n {q(ns)} --for=condition=Available deployment/{q(app)} --timeout=5m", "kubernetes/wait")
            add(f"Set the image for the app container in deployment {app} in {ns} to version 2.4.1", f"kubectl set image deployment/{q(app)} app={q('registry.example.com/' + app + ':2.4.1')} -n {q(ns)}", "kubernetes/images", "caution")
    pod_names = ["api-0", "web-0", "worker-0", "postgres-0", "redis-0", "gateway-0"]
    for ns in namespaces:
        for pod in pod_names:
            add(f"Show the last 100 log lines from pod {pod} in {ns}", f"kubectl logs {q(pod)} -n {q(ns)} --tail=100", "kubernetes/logs")
            add(f"Show logs from the previous instance of pod {pod} in {ns}", f"kubectl logs {q(pod)} -n {q(ns)} --previous", "kubernetes/logs")
            add(f"Print environment variables inside pod {pod} in {ns}", f"kubectl exec -n {q(ns)} {q(pod)} -- env", "kubernetes/exec", "caution")
            add(f"Check disk usage inside pod {pod} in namespace {ns}", f"kubectl exec -n {q(ns)} {q(pod)} -- df -h", "kubernetes/exec", "caution")
            add(f"Delete pod {pod} from namespace {ns}", f"kubectl delete pod {q(pod)} -n {q(ns)}", "kubernetes/deletion", "destructive")
    contexts = ["dev-us", "stage-eu", "prod-us", "prod-eu", "kind-local", "minikube"]
    for context in contexts:
        add(f"Switch kubectl to the {context} context", f"kubectl config use-context {q(context)}", "kubernetes/context", "caution")
        add(f"Show cluster information for kubectl context {context}", f"kubectl cluster-info --context {q(context)}", "kubernetes/context")
        add(f"List nodes in context {context}", f"kubectl get nodes --context {q(context)} -o wide", "kubernetes/nodes")
    add("List Kubernetes API resources that support namespaced objects", "kubectl api-resources --namespaced=true", "kubernetes/discovery")
    add("Show Kubernetes client and server versions", "kubectl version", "kubernetes/discovery")
    add("Display current resource consumption for every node", "kubectl top nodes", "kubernetes/metrics")
    add("List all pods that are not running across every namespace", "kubectl get pods -A --field-selector=status.phase!=Running", "kubernetes/pods")
    add("Preview deletion of resources from the stale manifest", "kubectl delete -f stale.yaml --dry-run=server", "kubernetes/deletion")


def helm() -> None:
    namespaces = ["staging", "production", "payments", "observability", "platform", "security", "data", "edge"]
    releases = ["api", "web", "prometheus", "grafana", "loki", "cert-manager", "external-dns", "ingress-nginx", "vault", "postgres"]
    for ns in namespaces:
        for release in releases:
            add(f"Show Helm status for release {release} in {ns}", f"helm status {q(release)} -n {q(ns)}", "helm/status")
            add(f"Get the deployed values for Helm release {release} in {ns}", f"helm get values {q(release)} -n {q(ns)} -a", "helm/values")
            add(f"Display the manifest for Helm release {release} in {ns}", f"helm get manifest {q(release)} -n {q(ns)}", "helm/manifest")
            add(f"Show revision history for Helm release {release} in {ns}", f"helm history {q(release)} -n {q(ns)}", "helm/history")
            add(f"Test Helm release {release} in namespace {ns}", f"helm test {q(release)} -n {q(ns)} --logs", "helm/testing", "caution")
            add(f"Uninstall Helm release {release} from {ns}", f"helm uninstall {q(release)} -n {q(ns)}", "helm/uninstall", "destructive")
    charts = ["api", "web", "worker", "gateway", "observability", "database"]
    for chart in charts:
        add(f"Lint the local {chart} Helm chart", f"helm lint {q('./charts/' + chart)}", "helm/lint")
        add(f"Render the local {chart} Helm chart for staging", f"helm template {q(chart)} {q('./charts/' + chart)} -n staging -f values-staging.yaml", "helm/template")
        add(f"Package the local {chart} Helm chart into dist", f"helm package {q('./charts/' + chart)} --destination dist", "helm/package", "caution")
        add(f"Show dependencies for the local {chart} Helm chart", f"helm dependency list {q('./charts/' + chart)}", "helm/dependencies")
        add(f"Update dependencies for the local {chart} Helm chart", f"helm dependency update {q('./charts/' + chart)}", "helm/dependencies", "caution")


def containers() -> None:
    engines = ["docker", "podman"]
    containers = ["api", "web", "worker", "postgres", "redis", "gateway", "grafana", "prometheus", "proxy", "scheduler"]
    images = ["api:1.4.0", "web:2.1.3", "worker:0.9.8", "gateway:3.0.1", "tools:latest", "backup:2026-07"]
    for engine in engines:
        add(f"List running containers using {engine}", f"{engine} ps", f"containers/{engine}/list")
        add(f"List all containers including stopped ones using {engine}", f"{engine} ps -a", f"containers/{engine}/list")
        add(f"Show disk usage for {engine} objects", f"{engine} system df", f"containers/{engine}/storage")
        add(f"Show detailed {engine} version information", f"{engine} version", f"containers/{engine}/info")
        for name in containers:
            add(f"Inspect the {name} container with {engine}", f"{engine} inspect {q(name)}", f"containers/{engine}/inspect")
            add(f"Show the last 200 logs from {name} using {engine}", f"{engine} logs --tail 200 {q(name)}", f"containers/{engine}/logs")
            add(f"Follow logs from container {name} using {engine}", f"{engine} logs -f --since 10m {q(name)}", f"containers/{engine}/logs")
            add(f"Show live resource usage once for container {name} using {engine}", f"{engine} stats --no-stream {q(name)}", f"containers/{engine}/metrics")
            add(f"Display processes running inside {name} using {engine}", f"{engine} top {q(name)}", f"containers/{engine}/processes")
            add(f"Stop container {name} gracefully with {engine}", f"{engine} stop --timeout 30 {q(name)}", f"containers/{engine}/lifecycle", "caution")
            add(f"Restart container {name} with {engine}", f"{engine} restart {q(name)}", f"containers/{engine}/lifecycle", "caution")
            add(f"Remove the stopped {name} container with {engine}", f"{engine} rm {q(name)}", f"containers/{engine}/removal", "destructive")
        for image in images:
            add(f"Inspect container image {image} with {engine}", f"{engine} image inspect {q(image)}", f"containers/{engine}/images")
            add(f"Pull container image {image} with {engine}", f"{engine} pull {q(image)}", f"containers/{engine}/images", "caution")
            add(f"Remove local container image {image} with {engine}", f"{engine} image rm {q(image)}", f"containers/{engine}/images", "destructive")
            add(f"Show the layer history for image {image} with {engine}", f"{engine} history {q(image)}", f"containers/{engine}/images")
    projects = ["api", "frontend", "worker", "gateway", "migration", "cli", "agent", "operator"]
    for project in projects:
        tag = f"registry.example.com/team/{project}:1.0.0"
        add(f"Build the {project} image with Docker BuildKit", f"docker build --pull -t {q(tag)} {q('./' + project)}", "containers/docker/build", "caution")
        add(f"Build the {project} image without Docker using Buildah", f"buildah bud -t {q(tag)} {q('./' + project)}", "containers/buildah/build", "caution")
        add(f"Inspect the {project} image using Skopeo without pulling it", f"skopeo inspect {q('docker://' + tag)}", "containers/skopeo/inspect")
        add(f"Copy the {project} image from the registry to an OCI archive", f"skopeo copy {q('docker://' + tag)} {q('oci-archive:' + project + '.tar:' + project)}", "containers/skopeo/copy", "caution")
        add(f"Copy the {project} image between registries with Skopeo", f"skopeo copy {q('docker://' + tag)} {q('docker://backup.example.com/team/' + project + ':1.0.0')}", "containers/skopeo/copy", "caution")
    for ctr in ["api", "web", "worker", "builder", "test-runner", "database"]:
        add(f"List Buildah containers matching {ctr}", f"buildah containers --filter {q('name=' + ctr)}", "containers/buildah/list")
        add(f"Inspect Buildah working container {ctr}", f"buildah inspect {q(ctr)}", "containers/buildah/inspect")
        add(f"Remove Buildah working container {ctr}", f"buildah rm {q(ctr)}", "containers/buildah/removal", "destructive")
    add("Remove unused Docker build cache older than one week", "docker builder prune --filter until=168h", "containers/docker/prune", "destructive")
    add("Remove all unused Podman images", "podman image prune -a", "containers/podman/prune", "destructive")
    add("Print the raw manifest for a remote container image", "skopeo inspect --raw docker://registry.example.com/team/api:1.0.0", "containers/skopeo/inspect")


def infrastructure_as_code() -> None:
    tools = ["terraform", "tofu"]
    stacks = ["network", "cluster", "database", "observability", "identity", "edge", "dns", "storage", "compute", "security"]
    workspaces = ["dev", "staging", "production", "dr", "sandbox"]
    for tool in tools:
        add(f"Show the installed {tool} version", f"{tool} version", f"iac/{tool}/info")
        add(f"Validate the {tool} configuration in the current directory", f"{tool} validate", f"iac/{tool}/validate")
        add(f"Check whether {tool} files need formatting", f"{tool} fmt -check -recursive", f"iac/{tool}/format")
        add(f"List resources in the current {tool} state", f"{tool} state list", f"iac/{tool}/state")
        add(f"List available {tool} workspaces", f"{tool} workspace list", f"iac/{tool}/workspace")
        add(f"Display provider requirements for the current {tool} project", f"{tool} providers", f"iac/{tool}/providers")
        for stack in stacks:
            directory = f"infra/{stack}"
            add(f"Initialize the {stack} {tool} stack without changing dependencies", f"{tool} -chdir={q(directory)} init -upgrade=false", f"iac/{tool}/init", "caution")
            add(f"Validate the {stack} {tool} stack", f"{tool} -chdir={q(directory)} validate", f"iac/{tool}/validate")
            add(f"Create a saved plan for the {stack} {tool} stack", f"{tool} -chdir={q(directory)} plan -out=tfplan", f"iac/{tool}/plan")
            add(f"Show the saved {tool} plan for {stack} as JSON", f"{tool} -chdir={q(directory)} show -json tfplan", f"iac/{tool}/show")
            add(f"Apply the saved plan for the {stack} {tool} stack", f"{tool} -chdir={q(directory)} apply tfplan", f"iac/{tool}/apply", "caution")
            add(f"Plan destruction of the {stack} {tool} stack without applying it", f"{tool} -chdir={q(directory)} plan -destroy", f"iac/{tool}/destroy-plan", "caution")
            add(f"Destroy the {stack} {tool} stack after approval", f"{tool} -chdir={q(directory)} destroy", f"iac/{tool}/destroy", "destructive")
            add(
                f"Display current outputs from the {stack} {tool} state as JSON",
                f"{tool} -chdir={q(directory)} output -json",
                f"iac/{tool}/output",
                "caution",
            )
        for ws in workspaces:
            add(f"Select the {ws} {tool} workspace", f"{tool} workspace select {q(ws)}", f"iac/{tool}/workspace", "caution")
            add(f"Select the {ws} {tool} workspace and show its resources", f"{tool} workspace select {q(ws)} >/dev/null && {tool} state list", f"iac/{tool}/workspace", "caution")
    resources = ["aws_vpc.main", "aws_eks_cluster.primary", "google_compute_network.main", "azurerm_resource_group.core", "kubernetes_namespace.platform", "helm_release.monitoring"]
    for resource in resources:
        add(f"Show the {resource} resource from Terraform state", f"terraform state show {q(resource)}", "iac/terraform/state")
        add(f"Remove {resource} from Terraform state without destroying the real resource", f"terraform state rm {q(resource)}", "iac/terraform/state", "destructive")


def ansible() -> None:
    inventories = ["dev", "staging", "production", "dr", "lab"]
    groups = ["web", "api", "workers", "database", "cache", "proxies", "monitoring", "bastions"]
    playbooks = ["site", "deploy", "patch", "hardening", "monitoring", "backup", "rotate-secrets", "rollback"]
    for inv in inventories:
        path = f"inventories/{inv}/hosts.yml"
        add(f"Display the Ansible inventory graph for {inv}", f"ansible-inventory -i {q(path)} --graph", "ansible/inventory")
        add(f"List the Ansible inventory for {inv} as JSON", f"ansible-inventory -i {q(path)} --list", "ansible/inventory")
        for group in groups:
            add(f"Ping the {group} hosts in the {inv} Ansible inventory", f"ansible {q(group)} -i {q(path)} -m ansible.builtin.ping", "ansible/ad-hoc")
            add(f"Gather facts from {group} hosts in the {inv} inventory", f"ansible {q(group)} -i {q(path)} -m ansible.builtin.setup", "ansible/facts")
            add(f"Check disk usage on {group} hosts in the {inv} inventory", f"ansible {q(group)} -i {q(path)} -a {q('df -h')}" , "ansible/ad-hoc")
            add(f"Run an Ansible connectivity check serially against {group} in {inv}", f"ansible {q(group)} -i {q(path)} -m ansible.builtin.ping --forks 1", "ansible/ad-hoc")
        for playbook in playbooks:
            file = f"playbooks/{playbook}.yml"
            add(f"Syntax-check the {playbook} Ansible playbook using the {inv} inventory", f"ansible-playbook -i {q(path)} {q(file)} --syntax-check", "ansible/playbook-check")
            add(f"Preview changes from the {playbook} playbook against {inv}", f"ansible-playbook -i {q(path)} {q(file)} --check --diff", "ansible/playbook-check")
            add(f"Run the {playbook} Ansible playbook against {inv}", f"ansible-playbook -i {q(path)} {q(file)}", "ansible/playbook-run", "caution")
    roles = ["nginx", "postgres", "node-exporter", "docker", "firewall", "users"]
    for role in roles:
        add(f"Lint the {role} Ansible role", f"ansible-lint {q('roles/' + role)}", "ansible/lint")
        add(f"Run Molecule tests for the {role} Ansible role", f"cd {q('roles/' + role)} && molecule test", "ansible/molecule", "caution")
        add(f"Verify the Molecule scenario for the {role} role", f"cd {q('roles/' + role)} && molecule verify", "ansible/molecule")


def cloud_clis() -> None:
    aws_regions = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ca-central-1"]
    aws_profiles = ["dev", "staging", "production", "security", "data"]
    for profile in aws_profiles:
        for region in aws_regions:
            suffix = f"--profile {q(profile)} --region {q(region)}"
            add(f"List EC2 instances for AWS profile {profile} in {region}", f"aws ec2 describe-instances {suffix} --query {q('Reservations[].Instances[].InstanceId')} --output text", "cloud/aws/ec2")
            add(f"List EKS clusters for AWS profile {profile} in {region}", f"aws eks list-clusters {suffix}", "cloud/aws/eks")
            add(f"List RDS database instances for AWS profile {profile} in {region}", f"aws rds describe-db-instances {suffix} --query {q('DBInstances[].DBInstanceIdentifier')} --output text", "cloud/aws/rds")
            add(f"List Lambda functions for AWS profile {profile} in {region}", f"aws lambda list-functions {suffix} --query {q('Functions[].FunctionName')} --output text", "cloud/aws/lambda")
            add(f"List CloudFormation stacks for AWS profile {profile} in {region}", f"aws cloudformation list-stacks {suffix} --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE", "cloud/aws/cloudformation")
            add(f"Show recent AWS CloudTrail events for profile {profile} in {region}", f"aws cloudtrail lookup-events {suffix} --max-results 20", "cloud/aws/cloudtrail")
            add(f"List running ECS tasks in cluster services for {profile} in {region}", f"aws ecs list-tasks --cluster services --desired-status RUNNING {suffix}", "cloud/aws/ecs")
            add(f"List load balancers for AWS profile {profile} in {region}", f"aws elbv2 describe-load-balancers {suffix} --query {q('LoadBalancers[].LoadBalancerName')} --output text", "cloud/aws/elb")
    buckets = ["app-artifacts", "audit-logs", "database-backups", "data-lake", "terraform-state", "frontend-assets"]
    for bucket in buckets:
        add(f"List objects at the root of S3 bucket {bucket}", f"aws s3 ls {q('s3://' + bucket + '/')}", "cloud/aws/s3")
        add(f"Recursively list object sizes in S3 bucket {bucket}", f"aws s3 ls {q('s3://' + bucket + '/')} --recursive --human-readable --summarize", "cloud/aws/s3")
        add(f"Synchronize the local backup directory to S3 bucket {bucket} and delete remote files missing locally", f"aws s3 sync backup/ {q('s3://' + bucket + '/backup/')} --delete", "cloud/aws/s3", "destructive")
        add(f"Remove the archived prefix from S3 bucket {bucket}", f"aws s3 rm {q('s3://' + bucket + '/archived/')} --recursive", "cloud/aws/s3", "destructive")
    clusters = ["platform-dev", "platform-stage", "platform-prod", "analytics-prod", "edge-prod"]
    for cluster in clusters:
        add(f"Update kubeconfig for EKS cluster {cluster}", f"aws eks update-kubeconfig --name {q(cluster)} --region us-east-1", "cloud/aws/eks", "caution")
        add(f"Describe the EKS cluster {cluster}", f"aws eks describe-cluster --name {q(cluster)} --region us-east-1", "cloud/aws/eks")
    gcp_projects = ["acme-dev", "acme-staging", "acme-prod", "acme-data", "acme-security", "acme-edge"]
    gcp_regions = ["us-central1", "us-east1", "europe-west1", "asia-southeast1"]
    for project in gcp_projects:
        add(f"List enabled services in Google Cloud project {project}", f"gcloud services list --enabled --project {q(project)}", "cloud/gcp/services")
        add(f"List service accounts in Google Cloud project {project}", f"gcloud iam service-accounts list --project {q(project)}", "cloud/gcp/iam")
        add(f"List GKE clusters in every region for Google Cloud project {project}", f"gcloud container clusters list --project {q(project)}", "cloud/gcp/gke")
        add(f"Show the effective gcloud configuration for project {project}", f"gcloud config list --project {q(project)}", "cloud/gcp/config")
        for region in gcp_regions:
            add(f"List Compute Engine instances in {region} for project {project}", f"gcloud compute instances list --project {q(project)} --filter {q('zone:(' + region + '-*)')}", "cloud/gcp/compute")
            add(f"List Cloud Run services in {region} for project {project}", f"gcloud run services list --region {q(region)} --project {q(project)}", "cloud/gcp/run")
            add(f"List Google Cloud SQL instances for project {project} from {region}", f"gcloud sql instances list --project {q(project)} --filter {q('region:' + region)}", "cloud/gcp/sql")
            add(f"List GKE clusters in {region} for project {project}", f"gcloud container clusters list --region {q(region)} --project {q(project)}", "cloud/gcp/gke")
    gke_clusters = ["dev-primary", "stage-primary", "prod-primary", "prod-analytics", "edge-services"]
    for cluster in gke_clusters:
        add(f"Fetch kubectl credentials for GKE cluster {cluster}", f"gcloud container clusters get-credentials {q(cluster)} --region us-central1 --project acme-prod", "cloud/gcp/gke", "caution")
        add(f"Describe GKE cluster {cluster}", f"gcloud container clusters describe {q(cluster)} --region us-central1 --project acme-prod", "cloud/gcp/gke")
    azure_subs = ["Development", "Staging", "Production", "Data", "Security", "Shared-Services"]
    resource_groups = ["rg-platform", "rg-apps", "rg-data", "rg-observability", "rg-network", "rg-security"]
    for subscription in azure_subs:
        add(f"Show details for Azure subscription {subscription}", f"az account show --subscription {q(subscription)}", "cloud/azure/account")
        add(f"List Azure resource groups in subscription {subscription}", f"az group list --subscription {q(subscription)} --output table", "cloud/azure/resource-groups")
        add(f"List AKS clusters in Azure subscription {subscription}", f"az aks list --subscription {q(subscription)} --output table", "cloud/azure/aks")
        for rg in resource_groups:
            add(f"List Azure resources in resource group {rg} under subscription {subscription}", f"az resource list --resource-group {q(rg)} --subscription {q(subscription)} --output table", "cloud/azure/resources")
            add(f"List Azure virtual machines in resource group {rg} under {subscription}", f"az vm list -g {q(rg)} --subscription {q(subscription)} --show-details --output table", "cloud/azure/vm")
            add(f"List Azure Key Vaults in resource group {rg} under {subscription}", f"az keyvault list -g {q(rg)} --subscription {q(subscription)} --output table", "cloud/azure/key-vault")
    aks_clusters = ["aks-dev", "aks-stage", "aks-prod", "aks-data", "aks-edge"]
    for cluster in aks_clusters:
        add(f"Fetch kubectl credentials for AKS cluster {cluster}", f"az aks get-credentials -g rg-platform -n {q(cluster)} --overwrite-existing", "cloud/azure/aks", "caution")
        add(f"Show available Kubernetes upgrades for AKS cluster {cluster}", f"az aks get-upgrades -g rg-platform -n {q(cluster)} --output table", "cloud/azure/aks")


def system_network_storage() -> None:
    services = ["nginx", "sshd", "docker", "containerd", "kubelet", "postgresql", "redis", "prometheus", "grafana-server", "node-exporter", "vault", "cron"]
    for service in services:
        add(f"Show systemd status for {service}", f"systemctl status {q(service)} --no-pager", "systemd/status")
        add(f"Check whether {service} is active", f"systemctl is-active {q(service)}", "systemd/status")
        add(f"Show whether {service} starts at boot", f"systemctl is-enabled {q(service)}", "systemd/status")
        add(f"Show logs for {service} from the current boot", f"journalctl -u {q(service)} -b --no-pager", "systemd/journal")
        add(f"Follow recent logs for {service}", f"journalctl -u {q(service)} -n 100 -f", "systemd/journal")
        add(f"Show warning and higher logs for {service} since yesterday", f"journalctl -u {q(service)} --since yesterday -p warning --no-pager", "systemd/journal")
        add(f"Restart the {service} systemd service", f"sudo systemctl restart {q(service)}", "systemd/lifecycle", "caution")
        add(f"Reload the {service} systemd service", f"sudo systemctl reload {q(service)}", "systemd/lifecycle", "caution")
    interfaces = ["eth0", "eth1", "ens3", "ens5", "bond0", "br0", "wg0", "cni0"]
    for iface in interfaces:
        add(f"Show addresses assigned to interface {iface}", f"ip address show dev {q(iface)}", "network/iproute2/address")
        add(f"Show link details for interface {iface}", f"ip -details link show dev {q(iface)}", "network/iproute2/link")
        add(f"Show routes using interface {iface}", f"ip route show dev {q(iface)}", "network/iproute2/route")
        add(f"Show traffic counters for interface {iface}", f"ip -s link show dev {q(iface)}", "network/iproute2/statistics")
        add(f"Display queueing disciplines on interface {iface}", f"tc qdisc show dev {q(iface)}", "network/tc/qdisc")
        add(f"Display traffic-control filters on interface {iface}", f"tc filter show dev {q(iface)}", "network/tc/filter")
        add(f"Add a 50 millisecond network delay to interface {iface}", f"sudo tc qdisc add dev {q(iface)} root netem delay 50ms", "network/tc/netem", "caution")
        add(f"Remove the root traffic-control rule from interface {iface}", f"sudo tc qdisc del dev {q(iface)} root", "network/tc/qdisc", "destructive")
    nft_tables = [("inet", "filter"), ("inet", "nat"), ("ip", "filter4"), ("ip6", "filter6")]
    for family, table in nft_tables:
        add(f"List the nftables {family} table named {table}", f"sudo nft list table {q(family)} {q(table)}", "network/nftables/list")
        add(f"List handles for rules in nftables table {family} {table}", f"sudo nft -a list table {q(family)} {q(table)}", "network/nftables/list")
        add(f"Create nftables table {family} named {table}", f"sudo nft add table {q(family)} {q(table)}", "network/nftables/configure", "caution")
        add(f"Delete nftables table {family} named {table}", f"sudo nft delete table {q(family)} {q(table)}", "network/nftables/delete", "destructive")
    wg_ifaces = ["wg0", "wg1", "wg-office", "wg-backup", "wg-site-a", "wg-site-b"]
    for iface in wg_ifaces:
        add(f"Show WireGuard status for interface {iface}", f"sudo wg show {q(iface)}", "network/wireguard/status")
        add(f"Show WireGuard peer transfer counters for {iface}", f"sudo wg show {q(iface)} transfer", "network/wireguard/status")
        add(f"Bring up WireGuard interface {iface}", f"sudo wg-quick up {q(iface)}", "network/wireguard/lifecycle", "caution")
        add(f"Bring down WireGuard interface {iface}", f"sudo wg-quick down {q(iface)}", "network/wireguard/lifecycle", "caution")
        add(f"Save the current WireGuard configuration for {iface}", f"sudo wg-quick save {q(iface)}", "network/wireguard/configure", "caution")
    zfs_datasets = ["tank/apps", "tank/backups", "tank/database", "tank/home", "pool/archive", "pool/vm"]
    for dataset in zfs_datasets:
        snap = f"{dataset}@pre-upgrade"
        add(f"Show ZFS properties for dataset {dataset}", f"zfs get all {q(dataset)}", "storage/zfs/properties")
        add(f"List snapshots under ZFS dataset {dataset}", f"zfs list -t snapshot -r {q(dataset)}", "storage/zfs/snapshots")
        add(f"Create a pre-upgrade ZFS snapshot of {dataset}", f"sudo zfs snapshot {q(snap)}", "storage/zfs/snapshots", "caution")
        add(f"Roll back ZFS dataset {dataset} to its pre-upgrade snapshot", f"sudo zfs rollback {q(snap)}", "storage/zfs/rollback", "destructive")
        add(f"Destroy the pre-upgrade ZFS snapshot of {dataset}", f"sudo zfs destroy {q(snap)}", "storage/zfs/destroy", "destructive")
        add(f"Estimate a full ZFS send for snapshot {snap}", f"zfs send -nPv {q(snap)}", "storage/zfs/send")
    btrfs_paths = ["/srv/data", "/srv/backups", "/var/lib/containers", "/home", "/mnt/archive", "/var/lib/postgresql"]
    for path in btrfs_paths:
        snap = f"{path}.snapshot"
        add(f"Show Btrfs filesystem usage for {path}", f"sudo btrfs filesystem usage {q(path)}", "storage/btrfs/usage")
        add(f"List Btrfs subvolumes beneath {path}", f"sudo btrfs subvolume list {q(path)}", "storage/btrfs/subvolume")
        add(f"Scrub the Btrfs filesystem mounted at {path} in the foreground", f"sudo btrfs scrub start -B {q(path)}", "storage/btrfs/scrub", "caution")
        add(f"Create a read-only Btrfs snapshot of {path}", f"sudo btrfs subvolume snapshot -r {q(path)} {q(snap)}", "storage/btrfs/snapshot", "caution")
        add(f"Delete the Btrfs snapshot at {snap}", f"sudo btrfs subvolume delete {q(snap)}", "storage/btrfs/delete", "destructive")
    lvs = [("vgdata", "apps"), ("vgdata", "database"), ("vgbackup", "daily"), ("vgvm", "guests"), ("vglogs", "journal"), ("vgshared", "media")]
    for vg, lv in lvs:
        path = f"/dev/{vg}/{lv}"
        snap = f"{lv}_snap"
        add(f"Show LVM details for logical volume {path}", f"sudo lvs -o +devices {q(path)}", "storage/lvm/inspect")
        add(f"Create a 5 gigabyte snapshot of logical volume {path}", f"sudo lvcreate -L 5G -s -n {q(snap)} {q(path)}", "storage/lvm/snapshot", "caution")
        add(f"Extend logical volume {path} by 10 gigabytes and resize its filesystem", f"sudo lvextend -r -L +10G {q(path)}", "storage/lvm/resize", "caution")
        add(f"Remove LVM snapshot {vg}/{snap}", f"sudo lvremove {q('/dev/' + vg + '/' + snap)}", "storage/lvm/remove", "destructive")
    vms = ["dev-api", "stage-web", "prod-db", "build-runner", "test-windows", "monitoring", "bastion", "router"]
    for vm in vms:
        add(f"Show virtual machine information for {vm}", f"virsh dominfo {q(vm)}", "virtualization/libvirt/info")
        add(f"Display XML configuration for virtual machine {vm}", f"virsh dumpxml {q(vm)}", "virtualization/libvirt/config")
        add(f"List block devices attached to virtual machine {vm}", f"virsh domblklist {q(vm)} --details", "virtualization/libvirt/storage")
        add(f"List network interfaces for virtual machine {vm}", f"virsh domiflist {q(vm)}", "virtualization/libvirt/network")
        add(f"Start virtual machine {vm}", f"virsh start {q(vm)}", "virtualization/libvirt/lifecycle", "caution")
        add(f"Gracefully shut down virtual machine {vm}", f"virsh shutdown {q(vm)}", "virtualization/libvirt/lifecycle", "caution")
        add(f"Force-stop unresponsive virtual machine {vm}", f"virsh destroy {q(vm)}", "virtualization/libvirt/lifecycle", "destructive")
        add(f"Create a disk-only snapshot of virtual machine {vm}", f"virsh snapshot-create-as {q(vm)} {q('pre-upgrade')} --disk-only --atomic", "virtualization/libvirt/snapshot", "caution")
    disks = ["debian.qcow2", "ubuntu.qcow2", "runner.qcow2", "database.qcow2", "router.qcow2", "windows.qcow2"]
    for disk in disks:
        add(f"Show QEMU image information for {disk}", f"qemu-img info {q(disk)}", "virtualization/qemu/image")
        add(f"Check the integrity of QEMU image {disk}", f"qemu-img check {q(disk)}", "virtualization/qemu/image")
        add(f"Create a compressed copy of QEMU image {disk}", f"qemu-img convert -p -O qcow2 -c {q(disk)} {q('compressed-' + disk)}", "virtualization/qemu/convert", "caution")


def observability_ci_secrets() -> None:
    prom_files = ["prometheus.yml", "rules/apps.yml", "rules/nodes.yml", "rules/kubernetes.yml", "rules/databases.yml", "alerts/security.yml"]
    for file in prom_files:
        kind = "config" if file == "prometheus.yml" else "rules"
        add(f"Validate Prometheus {kind} file {file}", f"promtool check {kind} {q(file)}", "observability/prometheus/validation")
    queries = ["up", "rate(http_requests_total[5m])", "sum by (job) (up)", "node_filesystem_avail_bytes", "kube_pod_status_phase", "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))"]
    for idx, query in enumerate(queries):
        add(f"Run Prometheus query number {idx + 1} against the local server", f"promtool query instant http://localhost:9090 {q(query)}", "observability/prometheus/query")
        add(f"Run Prometheus query number {idx + 1} over the last hour", f"promtool query range --start=1h --step=1m http://localhost:9090 {q(query)}", "observability/prometheus/query")
    loki_queries = [('{app="api"}', "API logs"), ('{namespace="production"} |= "error"', "production errors"), ('{job="nginx"} | json', "parsed Nginx logs"), ('sum by (level) (count_over_time({app="worker"}[5m]))', "worker log counts"), ('{cluster="prod"} != "healthcheck"', "production logs excluding health checks")]
    for query, label in loki_queries:
        add(f"Query Loki for {label} from the last hour", f"logcli query {q(query)} --since=1h --limit=200", "observability/loki/query")
        add(f"Query Loki for {label} and stream new results", f"logcli query {q(query)} --since=10m --tail", "observability/loki/tail")
    alert_filters = ["alertname=HighErrorRate", "severity=critical", "team=platform", "cluster=production", "service=api"]
    for matcher in alert_filters:
        add(f"List Alertmanager alerts matching {matcher}", f"amtool alert query {q(matcher)}", "observability/alertmanager/query")
        add(f"Create a two-hour Alertmanager silence matching {matcher}", f"amtool silence add {q(matcher)} --duration=2h --comment={q('maintenance window')} --author={q('platform-team')}", "observability/alertmanager/silence", "caution")
    otel_configs = ["otelcol.yaml", "otelcol-agent.yaml", "otelcol-gateway.yaml", "otelcol-traces.yaml", "otelcol-metrics.yaml", "otelcol-logs.yaml"]
    for config in otel_configs:
        add(f"Validate the OpenTelemetry Collector configuration {config}", f"otelcol validate --config={q(config)}", "observability/opentelemetry/validation")
        add(f"Run the OpenTelemetry Collector with configuration {config}", f"otelcol --config={q(config)}", "observability/opentelemetry/collector", "caution")
    services = ["api", "web", "worker", "gateway", "billing", "catalog", "notifications", "scheduler"]
    for service in services:
        add(f"Emit a test OpenTelemetry span for service {service}", f"otel-cli span --service {q(service)} --name {q('smoke-test')} --endpoint http://localhost:4317", "observability/opentelemetry/span", "caution")
        add(f"Run a health check inside an OpenTelemetry span for {service}", f"otel-cli exec --service {q(service)} --name {q('health-check')} -- curl -fsS http://localhost:8080/health", "observability/opentelemetry/span")
    runner_names = ["linux-x64-01", "linux-x64-02", "linux-arm64-01", "gpu-01", "windows-01", "macos-01"]
    for runner in runner_names:
        add(f"Show the systemd status of GitHub Actions runner {runner}", f"systemctl status {q('actions.runner.acme-project.' + runner + '.service')} --no-pager", "ci/github-actions/runner")
        add(f"Follow logs for GitHub Actions runner {runner}", f"journalctl -u {q('actions.runner.acme-project.' + runner + '.service')} -f", "ci/github-actions/runner")
        add(f"Restart GitHub Actions runner {runner}", f"sudo systemctl restart {q('actions.runner.acme-project.' + runner + '.service')}", "ci/github-actions/runner", "caution")
    gitlab_runners = ["docker-1", "docker-2", "shell-1", "kubernetes-1", "gpu-1", "arm64-1"]
    for runner in gitlab_runners:
        add(f"Verify connectivity for GitLab Runner configuration {runner}", f"gitlab-runner verify --name {q(runner)}", "ci/gitlab/runner")
        add(f"Run GitLab Runner configuration {runner} in debug mode", f"gitlab-runner --debug run-single --name {q(runner)}", "ci/gitlab/runner", "caution")
        add(f"Unregister GitLab Runner named {runner}", f"gitlab-runner unregister --name {q(runner)}", "ci/gitlab/runner", "destructive")
    secret_files = ["secrets/dev.yaml", "secrets/staging.yaml", "secrets/production.yaml", "secrets/database.yaml", "secrets/monitoring.yaml", "secrets/registry.yaml"]
    password_path = '["database"]["password"]'
    for file in secret_files:
        add(f"Decrypt SOPS file {file} to standard output", f"sops --decrypt {q(file)}", "secrets/sops/decrypt", "caution")
        add(f"Show the database password field from SOPS file {file}", f"sops --decrypt --extract {q(password_path)} {q(file)}", "secrets/sops/decrypt", "caution")
        add(f"Rotate data keys in SOPS file {file} in place", f"sops updatekeys --yes {q(file)}", "secrets/sops/keys", "caution")
    vault_paths = ["secret/apps/api", "secret/apps/web", "secret/database/postgres", "secret/ci/registry", "secret/monitoring/grafana", "secret/network/wireguard"]
    for path in vault_paths:
        add(f"Read the Vault secret at {path}", f"vault kv get {q(path)}", "secrets/vault/read", "caution")
        add(f"Read the token field from Vault secret {path}", f"vault kv get -field=token {q(path)}", "secrets/vault/read", "caution")
        add(f"Display Vault metadata for secret {path}", f"vault kv metadata get {q(path)}", "secrets/vault/metadata", "caution")
        add(f"Delete all versions and metadata for Vault secret {path}", f"vault kv metadata delete {q(path)}", "secrets/vault/delete", "destructive")
    age_files = ["database.env", "production.env", "registry.json", "backup-key.txt", "wireguard.conf", "terraform.tfvars"]
    for file in age_files:
        add(f"Encrypt {file} for the recipients listed in operations-recipients.txt", f"age -R operations-recipients.txt -o {q(file + '.age')} {q(file)}", "secrets/age/encrypt", "caution")
        add(f"Decrypt age file {file}.age to standard output", f"age --decrypt {q(file + '.age')}", "secrets/age/decrypt", "caution")
    cosign_images = ["registry.example.com/api:1.0", "registry.example.com/web:2.0", "registry.example.com/worker:3.1", "registry.example.com/gateway:4.2"]
    for image in cosign_images:
        add(f"Verify the keyless Cosign signature on image {image}", f"cosign verify {q(image)}", "secrets/supply-chain/verify")
        add(f"Download the software bill of materials attached to image {image}", f"cosign download sbom {q(image)}", "secrets/supply-chain/sbom")


def main() -> None:
    kubernetes()
    helm()
    containers()
    infrastructure_as_code()
    ansible()
    cloud_clis()
    system_network_storage()
    observability_ci_secrets()

    assert len(ROWS) >= 3600, f"only generated {len(ROWS)} rows"
    assert len(SEEN_NL) == len(ROWS) == len(SEEN_BASH)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(ROWS, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    reloaded = json.loads(OUTPUT.read_text(encoding="utf-8"))
    required = {"nl", "bash", "category", "risk", "source", "family"}
    assert isinstance(reloaded, list) and len(reloaded) == len(ROWS)
    assert all(set(row) == required for row in reloaded)
    assert all(all(isinstance(value, str) and value for value in row.values()) for row in reloaded)
    assert all(row["source"] == "manual-curation" for row in reloaded)
    assert all(row["risk"] in RISKS for row in reloaded)
    assert all("\n" not in row["bash"] and "\r" not in row["bash"] for row in reloaded)
    assert len({row["nl"] for row in reloaded}) == len(reloaded)
    assert len({row["bash"] for row in reloaded}) == len(reloaded)
    expected_domains = {
        "kubernetes", "helm", "containers", "iac", "ansible", "cloud", "systemd",
        "network", "storage", "virtualization", "observability", "ci", "secrets",
    }
    assert expected_domains <= {row["category"].split("/", 1)[0] for row in reloaded}
    categories = len({row["category"] for row in ROWS})
    risks = {risk: sum(row["risk"] == risk for row in ROWS) for risk in sorted(RISKS)}
    print(f"wrote {len(ROWS)} unique rows across {categories} categories to {OUTPUT}")
    print("risk counts:", risks)


if __name__ == "__main__":
    main()
