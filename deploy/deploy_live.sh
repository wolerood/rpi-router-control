#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this script through sudo" >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STAGING_DIR=${STAGING_DIR:-$(dirname "$SCRIPT_DIR")}
LIVE_DIR=${LIVE_DIR:-/home/pi/rpi-router-api}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
BACKUP_ROOT=${BACKUP_ROOT:-/var/backups/rpi-router}
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$BACKUP_ROOT/$STAMP

required_files="
access_policy.py
app.py
database.py
firewall.py
schedule_check.py
schedule_engine.py
requirements.txt
README.md
deploy/systemd/rpi-schedule-engine.service
deploy/systemd/rpi-schedule-engine.timer
"

for relative_path in $required_files; do
    if [ ! -f "$STAGING_DIR/$relative_path" ]; then
        echo "ERROR: missing staging file: $relative_path" >&2
        exit 1
    fi
done

python3 -m compileall -q "$STAGING_DIR"
(
    cd "$STAGING_DIR"
    RPI_ROUTER_DB_PATH="$STAGING_DIR/router.db" \
        PYTHONPATH="$STAGING_DIR" \
        python3 -m unittest discover -s tests -t . -q
)

mkdir -p "$BACKUP_DIR"

systemctl is-enabled block-phone.timer >"$BACKUP_DIR/block-phone.enabled" 2>/dev/null || true
systemctl is-enabled unblock-phone.timer >"$BACKUP_DIR/unblock-phone.enabled" 2>/dev/null || true

systemctl stop rpi-schedule-engine.timer
systemctl stop rpi-router-api.service

sqlite3 "$LIVE_DIR/router.db" ".backup '$BACKUP_DIR/router.db'"
tar -czf "$BACKUP_DIR/code.tar.gz" \
    --exclude='./router.db' \
    --exclude='./router.db-wal' \
    --exclude='./router.db-shm' \
    --exclude='./__pycache__' \
    -C "$LIVE_DIR" .

for unit in \
    rpi-router-api.service \
    rpi-schedule-engine.service \
    rpi-schedule-engine.timer \
    block-phone.service \
    block-phone.timer \
    unblock-phone.service \
    unblock-phone.timer
do
    if [ -f "$SYSTEMD_DIR/$unit" ]; then
        cp -a "$SYSTEMD_DIR/$unit" "$BACKUP_DIR/$unit"
    fi
done

for source_file in \
    access_policy.py \
    app.py \
    database.py \
    firewall.py \
    schedule_check.py \
    schedule_engine.py
do
    install -o pi -g pi -m 0644 \
        "$STAGING_DIR/$source_file" "$LIVE_DIR/$source_file"
done

install -o pi -g pi -m 0644 "$STAGING_DIR/README.md" "$LIVE_DIR/README.md"
install -o pi -g pi -m 0644 "$STAGING_DIR/requirements.txt" "$LIVE_DIR/requirements.txt"

RPI_ROUTER_DB_PATH="$LIVE_DIR/router.db" python3 "$LIVE_DIR/database.py"
chown pi:pi "$LIVE_DIR/router.db"
chmod 0640 "$LIVE_DIR/router.db"

install -o root -g root -m 0644 \
    "$STAGING_DIR/deploy/systemd/rpi-schedule-engine.service" \
    "$SYSTEMD_DIR/rpi-schedule-engine.service"
install -o root -g root -m 0644 \
    "$STAGING_DIR/deploy/systemd/rpi-schedule-engine.timer" \
    "$SYSTEMD_DIR/rpi-schedule-engine.timer"

systemctl disable --now block-phone.timer unblock-phone.timer
systemctl daemon-reload

systemctl start rpi-schedule-engine.service
systemctl enable --now rpi-schedule-engine.timer
systemctl restart rpi-router-api.service

systemctl is-active --quiet rpi-router-api.service
systemctl is-active --quiet rpi-schedule-engine.timer

api_ready=false
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl --fail --silent http://127.0.0.1:8080/users >/dev/null; then
        api_ready=true
        break
    fi
    sleep 1
done

if [ "$api_ready" != true ]; then
    echo "ERROR: API did not become ready within 10 seconds" >&2
    exit 1
fi

echo "DEPLOYMENT_OK"
echo "BACKUP_DIR=$BACKUP_DIR"
