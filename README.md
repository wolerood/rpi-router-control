# RPi Router Control API

Server-side access control for a Raspberry Pi Wi-Fi router. The Flask API
stores users, devices and schedules in SQLite. A systemd timer reconciles the
desired policy with the `inet parental_control blocked_macs` nftables set.

## Policy

- Weekdays use ISO numbering (`1` is Monday, `7` is Sunday).
- Times use zero-padded local `HH:MM` values.
- Both ends of an interval are inclusive.
- An interval whose start is later than its end crosses midnight.
- An empty schedule blocks access.
- Manual `always_allow` and `always_block` modes override schedules.
- MAC addresses are stored as lower-case colon-separated values.

The Raspberry Pi must use the `Europe/Moscow` time zone.

## Database

Create or migrate the schema with:

```sh
python3 database.py
```

The migration is idempotent, records its schema version, enables foreign keys
on every connection and switches the database to WAL mode.

Before deploying a new version, back up `router.db` together with any existing
`router.db-wal` and `router.db-shm` files while both API and schedule-engine
services are stopped.

## Tests

The test suite uses only the Python standard library:

```sh
python3 -m unittest discover -s tests -v
```

Tests do not call the host nftables service.

## Runtime

`schedule_engine.py` treats `blocked_macs` as application-owned state. During
each run it:

1. reads the actual nftables set;
2. removes blocked MACs which no longer belong to registered devices;
3. removes stale `device_state` rows;
4. evaluates every registered device through the shared policy module;
5. changes nftables only when actual and desired state differ;
6. writes history only when ALLOW/BLOCK changes.

The timer templates in `deploy/systemd` use a one-second accuracy window so a
policy is reconciled no later than approximately one minute after the previous
run completes.

At boot, `parental-control.service` creates the nftables table before
NetworkManager starts and runs `restore_firewall.py`. The restore step loads
the last successfully recorded `BLOCK` states for devices which are still
registered. This preserves the last applied restrictions until the schedule
engine performs its first full policy reconciliation.

Legacy `block-phone.timer` and `unblock-phone.timer` units must be disabled
before enabling this timer. There must be only one writer for `blocked_macs`.

## Configuration

The following environment variables are supported:

- `RPI_ROUTER_DB_PATH` — SQLite file path;
- `RPI_ROUTER_LOG_PATH` — transition/cleanup log path;
- `RPI_ROUTER_NFT_BINARY` — absolute `nft` executable path.

The current API remains unauthenticated and must not be published directly to
the internet. Remote access hardening is tracked as a separate deployment
stage.

The production service uses the Debian `gunicorn` package with two threaded
workers. Install it before deployment:

```sh
sudo apt update
sudo apt install gunicorn
```

The systemd unit keeps the existing `0.0.0.0:8080` listener and restarts the
process on failure. It also applies baseline filesystem, kernel and namespace
hardening without restricting the nftables and Wi-Fi diagnostics used by the
API.

`GET /status` is the health endpoint for clients and monitoring. It returns the
API version, local timestamp, database schema and object counts, plus the
number of MAC addresses currently blocked by nftables. HTTP 503 means that the
database or firewall control path is unavailable; the response body identifies
the failed component.

## Write authentication

All `POST`, `PATCH` and `DELETE` requests require an `X-API-Token` header.
Read-only `GET` requests remain available without authentication. Deployment
creates a 256-bit random token once in `/etc/rpi-router-api.env`, owned by root
with mode `0600`; later deployments preserve the same token. The API refuses
all write requests if the token is missing from the service environment.

Display the token locally on the Raspberry Pi when configuring a trusted
client:

```sh
sudo sed -n 's/^RPI_ROUTER_API_TOKEN=//p' /etc/rpi-router-api.env
```

The token is not encryption. Plain HTTP is acceptable only on the trusted home
network. Internet access must terminate TLS or use a private VPN/tunnel before
the API is exposed remotely.
