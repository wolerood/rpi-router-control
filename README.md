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
