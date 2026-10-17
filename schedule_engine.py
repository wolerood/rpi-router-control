import os
from datetime import datetime

from access_policy import check_user_access, normalize_mac
from database import get_connection, init_database
from firewall import FirewallError, allow_mac, block_mac, get_blocked_macs


LOG_FILE = os.environ.get(
    "RPI_ROUTER_LOG_PATH",
    "/var/log/rpi-router/access.log",
)


def write_log(message):
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")


def write_access_log(
    cur,
    mac,
    device_name,
    user_name,
    action,
    reason,
    timestamp,
):
    cur.execute(
        """
        INSERT INTO access_log (
            device_mac,
            device_name,
            user_name,
            action,
            reason,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (mac, device_name, user_name, action, reason, timestamp),
    )


def get_previous_state(cur, mac):
    cur.execute(
        "SELECT action, reason FROM device_state WHERE mac = ?",
        (mac,),
    )
    return cur.fetchone()


def update_state(
    cur,
    mac,
    device_name,
    user_name,
    action,
    reason,
    timestamp,
):
    cur.execute(
        """
        INSERT INTO device_state (
            mac,
            device_name,
            user_name,
            action,
            reason,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            device_name = excluded.device_name,
            user_name = excluded.user_name,
            action = excluded.action,
            reason = excluded.reason,
            timestamp = excluded.timestamp
        """,
        (mac, device_name, user_name, action, reason, timestamp),
    )


def remove_stale_state(cur, managed_macs):
    if not managed_macs:
        cur.execute("DELETE FROM device_state")
        return cur.rowcount

    placeholders = ", ".join("?" for _ in managed_macs)
    cur.execute(
        f"DELETE FROM device_state WHERE lower(mac) NOT IN ({placeholders})",
        tuple(sorted(managed_macs)),
    )
    return cur.rowcount


def format_message(now, user_name, device_name, mac, action, reason):
    return (
        f"{now:%Y-%m-%d %H:%M:%S} | "
        f"{user_name} | {device_name} | {mac} | {action} | {reason}"
    )


def main():
    now = datetime.now()
    timestamp = f"{now:%Y-%m-%d %H:%M:%S}"

    try:
        init_database()
        blocked_macs = get_blocked_macs()
    except Exception as error:
        print(f"{timestamp} | ERROR | initialization failed: {error}")
        return 1

    conn = get_connection()
    cur = conn.cursor()
    exit_code = 0

    try:
        cur.execute(
            """
            SELECT devices.mac, devices.name, users.id, users.name
            FROM devices
            JOIN users ON devices.user_id = users.id
            ORDER BY devices.id
            """
        )
        devices = cur.fetchall()

        managed_macs = set()
        normalized_devices = []

        for mac, device_name, user_id, user_name in devices:
            try:
                normalized_mac = normalize_mac(mac)
            except ValueError as error:
                print(
                    format_message(
                        now,
                        user_name,
                        device_name,
                        str(mac),
                        "ERROR",
                        str(error),
                    )
                )
                exit_code = 1
                continue

            managed_macs.add(normalized_mac)
            normalized_devices.append(
                (normalized_mac, device_name, user_id, user_name)
            )

        # This set is owned exclusively by this application. Remove firewall
        # entries for devices which are no longer registered.
        for orphan_mac in sorted(blocked_macs - managed_macs):
            try:
                allow_mac(orphan_mac)
                blocked_macs.remove(orphan_mac)
                message = f"{timestamp} | ORPHAN | {orphan_mac} | ALLOW | removed"
                print(message)
                write_log(message)
            except FirewallError as error:
                print(
                    f"{timestamp} | ORPHAN | {orphan_mac} | ERROR | "
                    f"cannot remove from blocked_macs: {error}"
                )
                exit_code = 1

        removed_states = remove_stale_state(cur, managed_macs)
        if removed_states:
            message = (
                f"{timestamp} | CLEANUP | removed stale device_state rows: "
                f"{removed_states}"
            )
            print(message)
            write_log(message)

        for mac, device_name, user_id, user_name in normalized_devices:
            decision = check_user_access(
                cur,
                user_id,
                now.isoweekday(),
                now.strftime("%H:%M"),
            )
            allowed = decision["allowed"]
            reason = decision["reason"]

            if allowed is None:
                print(
                    format_message(
                        now,
                        user_name,
                        device_name,
                        mac,
                        "ERROR",
                        reason,
                    )
                )
                exit_code = 1
                continue

            try:
                if allowed and mac in blocked_macs:
                    allow_mac(mac)
                    blocked_macs.remove(mac)
                elif not allowed and mac not in blocked_macs:
                    block_mac(mac)
                    blocked_macs.add(mac)
            except FirewallError as error:
                print(
                    format_message(
                        now,
                        user_name,
                        device_name,
                        mac,
                        "ERROR",
                        f"cannot update blocked_macs: {error}",
                    )
                )
                exit_code = 1
                continue

            action = "ALLOW" if allowed else "BLOCK"
            previous = get_previous_state(cur, mac)
            state_changed = previous is None or previous[0] != action
            details_changed = (
                state_changed or previous is None or previous[1] != reason
            )

            if state_changed:
                write_access_log(
                    cur,
                    mac,
                    device_name,
                    user_name,
                    action,
                    reason,
                    timestamp,
                )

            if details_changed:
                update_state(
                    cur,
                    mac,
                    device_name,
                    user_name,
                    action,
                    reason,
                    timestamp,
                )
                message = format_message(
                    now,
                    user_name,
                    device_name,
                    mac,
                    action,
                    reason,
                )
                print(message)
                write_log(message)

        conn.commit()
    except Exception as error:
        conn.rollback()
        print(f"{timestamp} | ERROR | reconciliation failed: {error}")
        return 1
    finally:
        conn.close()

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
