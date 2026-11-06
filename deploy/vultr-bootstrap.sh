#!/usr/bin/env bash
# Bootstrap the Blast Radius demo on a fresh Ubuntu 24.04 Vultr VM.
#
#   sudo BLAST_RADIUS_DOMAIN=demo.example.com \
#        bash deploy/vultr-bootstrap.sh https://github.com/pham-canh/blast-radius-zero.git main
#
# The app runs directly on the VM (it must call `docker run`), not in a container.
# Caddy provides HTTPS; without a domain the script uses <public-ip>.sslip.io.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this script as root (sudo)." >&2
    exit 1
fi

REPO_URL="${1:-}"
BRANCH="${2:-main}"
APP_DIR="${APP_DIR:-/opt/blast-radius}"
DOMAIN="${BLAST_RADIUS_DOMAIN:-}"

if [[ -z "${REPO_URL}" ]]; then
    cat >&2 <<'USAGE'
Usage: sudo bash deploy/vultr-bootstrap.sh <repo-url> [branch]

Environment:
  BLAST_RADIUS_DOMAIN=demo.example.com   optional; defaults to <vm-ip>.sslip.io
  APP_DIR=/opt/blast-radius          install directory
USAGE
    exit 2
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl git python3 python3-venv python3-pip docker.io

# A stock Ubuntu image can ship with UFW active and only port 22 open. Caddy
# needs 80/443 for the certificate; 7860 is the app itself for local checks.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 22/tcp >/dev/null || true
    ufw allow 80/tcp >/dev/null || true
    ufw allow 443/tcp >/dev/null || true
    ufw allow 7860/tcp >/dev/null || true
    echo "UFW is active; opened 22, 80, 443, 7860."
fi

HAVE_CADDY=1
if ! command -v caddy >/dev/null 2>&1; then
    if ! apt-get install -y caddy; then
        HAVE_CADDY=0
        echo "WARNING: Caddy is not available; HTTPS will be skipped." >&2
    fi
fi

systemctl enable --now docker

# The service runs with ProtectHome=true, so Docker cannot use /root/.docker.
# Give it an explicit config directory and pull the base image before the demo.
install -d -m 750 /var/lib/blast-radius/.docker
docker pull python:3.11-slim >/dev/null 2>&1 || \
    echo "WARNING: could not pre-pull python:3.11-slim; first run will pull it." >&2

if ! id blastradius >/dev/null 2>&1; then
    useradd --system --create-home --shell /usr/sbin/nologin blastradius
fi
usermod -aG docker blastradius

mkdir -p "${APP_DIR}"
if [[ -d "${APP_DIR}/.git" ]]; then
    git -C "${APP_DIR}" fetch --depth=1 origin "${BRANCH}"
    git -C "${APP_DIR}" checkout -B "${BRANCH}" "origin/${BRANCH}"
else
    git clone --depth=1 --branch "${BRANCH}" "${REPO_URL}" "${APP_DIR}"
fi

SOURCE_DIR="${APP_DIR}"
if [[ ! -f "${SOURCE_DIR}/app.py" ]]; then
    echo "app.py not found in ${SOURCE_DIR}." >&2
    exit 1
fi

python3 -m venv "${SOURCE_DIR}/.venv"
"${SOURCE_DIR}/.venv/bin/pip" install --upgrade pip >/dev/null
"${SOURCE_DIR}/.venv/bin/pip" install -r "${SOURCE_DIR}/requirements.txt"

install -d -o blastradius -g blastradius /var/lib/blast-radius
install -d -o blastradius -g blastradius /var/lib/blast-radius/attestations
install -d -o blastradius -g blastradius -m 750 /var/lib/blast-radius/.docker
install -d -m 750 /etc/blast-radius

ENV_FILE=/etc/blast-radius/blast-radius.env
if [[ ! -f "${ENV_FILE}" ]]; then
    cat > "${ENV_FILE}" <<'ENV'
# Fill in the key and one live model id, then:
#   sudo systemctl restart blast-radius
INFERENCE_PROVIDER=vultr
INFERENCE_BASE_URL=https://api.vultrinference.com/v1
INFERENCE_MODEL=
INFERENCE_API_KEY=

BLAST_RADIUS_BACKEND=vultr
BLAST_RADIUS_OUTDIR=/var/lib/blast-radius/attestations
BLAST_RADIUS_HISTORY=/var/lib/blast-radius/history.jsonl
DOCKER_CONFIG=/var/lib/blast-radius/.docker
ENV
    chmod 600 "${ENV_FILE}"
    echo "Created ${ENV_FILE}. Add INFERENCE_API_KEY and INFERENCE_MODEL before the demo."
fi

if ! grep -q '^DOCKER_CONFIG=' "${ENV_FILE}"; then
    printf '\nDOCKER_CONFIG=/var/lib/blast-radius/.docker\n' >> "${ENV_FILE}"
fi

IP="$(curl -fsS --max-time 5 https://api.ipify.org || true)"
if [[ -z "${DOMAIN}" ]]; then
    DOMAIN="${IP:-localhost}.sslip.io"
fi

if [[ "${HAVE_CADDY}" -eq 1 ]]; then
    cat > /etc/caddy/Caddyfile <<CADDY
${DOMAIN} {
    encode gzip
    reverse_proxy 127.0.0.1:7860
}
CADDY
    systemctl enable --now caddy
    systemctl reload caddy || systemctl restart caddy
fi

sed "s|__APP_DIR__|${SOURCE_DIR}|g" \
    "${SOURCE_DIR}/deploy/blast-radius.service" \
    > /etc/systemd/system/blast-radius.service
systemctl daemon-reload
systemctl enable --now blast-radius
systemctl restart blast-radius

READY=0
for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:7860/healthz >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 2
done

if [[ "${READY}" -ne 1 ]]; then
    echo "App did not become healthy. Inspect:" >&2
    echo "  journalctl -u blast-radius -n 100 --no-pager" >&2
    exit 1
fi

if ! grep -qE '^INFERENCE_API_KEY=.+$' "${ENV_FILE}"; then
    echo "WARNING: INFERENCE_API_KEY is empty; the UI will report SKIPPED." >&2
fi
if ! grep -qE '^INFERENCE_MODEL=.+$' "${ENV_FILE}"; then
    echo "WARNING: INFERENCE_MODEL is empty; the UI will report SKIPPED." >&2
fi

# Prove the service account can really spawn a container, not just that the
# process is listening. A failure here is a warning, not a deploy abort: the
# demo URL is still useful for inspecting the report.
echo
echo "Verifying containment as the blastradius user..."
if ! runuser -u blastradius -- env HOME=/var/lib/blast-radius \
        DOCKER_CONFIG=/var/lib/blast-radius/.docker \
        "${SOURCE_DIR}/.venv/bin/python" "${SOURCE_DIR}/src/main.py" --probe; then
    echo "WARNING: containment probe failed; check Docker group membership." >&2
fi

echo
if [[ "${HAVE_CADDY}" -eq 1 ]]; then
    echo "Blast Radius is up: https://${DOMAIN}/"
    echo "Health:             https://${DOMAIN}/healthz"
else
    echo "Blast Radius is up: http://${IP:-<vm-ip>}:7860/"
    echo "Health:             http://127.0.0.1:7860/healthz"
fi
echo "Logs:               journalctl -u blast-radius -f"
echo "Attestations:       /var/lib/blast-radius/attestations/"
