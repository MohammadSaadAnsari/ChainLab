#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"
controller_started=false
log_dir="${SFC_LOG_DIR:-/tmp/sfc-demo-logs}"
log_file="$log_dir/controller.log"

cleanup() {
    if [[ "$controller_started" == true ]]; then
        docker logs sfc-controller >"$log_file" 2>&1 || true
        docker rm -f sfc-controller >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if [[ "${1:-}" == "--help" ]]; then
    printf 'Usage: sudo ./run_demo.sh [--no-build]\n'
    exit 0
fi
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != "--no-build" ) ]]; then
    printf 'Unknown argument. Use --help.\n' >&2
    exit 2
fi
if [[ $EUID -ne 0 ]]; then
    printf 'Run as root: sudo ./run_demo.sh\n' >&2
    exit 1
fi
for program in docker ovs-vsctl ovs-ofctl ip nsenter python3; do
    command -v "$program" >/dev/null || { printf 'Missing %s\n' "$program" >&2; exit 1; }
done
if ! python3 -c 'import mininet' >/dev/null 2>&1; then
    printf 'Mininet is unavailable to host python3. Install python3-mininet/mininet.\n' >&2
    exit 1
fi
docker info >/dev/null

# A reboot can leave the non-restarting controller container in Docker's
# stopped state, where it still reserves the name used by the next run.
if docker container inspect sfc-controller >/dev/null 2>&1; then
    if [[ "$(docker inspect -f '{{.State.Running}}' sfc-controller)" == true ]]; then
        printf 'sfc-controller is already running. Exit the existing demo before starting another.\n' >&2
        exit 1
    fi
    printf 'Removing stopped sfc-controller from the previous run...\n'
    docker rm sfc-controller >/dev/null
fi

if [[ "${1:-}" != "--no-build" ]]; then
    for service in controller firewall ids policer; do
        printf '\nBuilding %s image...\n' "$service"
        if [[ "$service" == controller ]]; then
            dockerfile="$project_dir/controller/Dockerfile"
        else
            dockerfile="$project_dir/vnf_configs/$service/Dockerfile"
        fi
        docker build -t "sfc-${service}:latest" \
            -f "$dockerfile" "$project_dir"
    done
fi

export SFC_API_TOKEN="${SFC_API_TOKEN:-$(python3 -c 'import secrets; print(secrets.token_hex(16))')}"
mkdir -p "$log_dir"
docker run -d --network host --cap-drop ALL --security-opt no-new-privileges \
    --env SFC_API_TOKEN --name sfc-controller sfc-controller:latest >/dev/null
controller_started=true

ready=false
for _ in $(seq 1 60); do
    if python3 -c 'from urllib.request import urlopen; urlopen("http://127.0.0.1:8080/sfc/status", timeout=0.3).close()' \
        >/dev/null 2>&1; then
        ready=true
        break
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' sfc-controller)" != true ]]; then
        break
    fi
    sleep 0.2
done
if [[ "$ready" != true ]]; then
    printf 'Ryu failed to start. Recent log lines:\n' >&2
    docker logs --tail 30 sfc-controller >&2 || true
    exit 1
fi

printf '\nSFC controller ready.\n'
printf 'Dashboard: http://127.0.0.1:8080/sfc\n'
printf 'Dashboard control token: %s\n' "$SFC_API_TOKEN"
printf 'Controller log: %s\n\n' "$log_file"
python3 "$project_dir/sfc_topology.py"
