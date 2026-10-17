from datetime import datetime

from access_policy import check_user_access
from database import get_connection, init_database


def check_access(user_id, now=None):
    now = now or datetime.now()
    conn = get_connection()

    try:
        result = check_user_access(
            conn.cursor(),
            user_id,
            now.isoweekday(),
            now.strftime("%H:%M"),
        )
        return result["allowed"], result["reason"]
    finally:
        conn.close()


def check_devices(now=None):
    now = now or datetime.now()
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT devices.name, devices.mac, users.name, users.id
            FROM devices
            JOIN users ON devices.user_id = users.id
            ORDER BY devices.id
            """
        )
        devices = cur.fetchall()

        for device_name, mac, user_name, user_id in devices:
            result = check_user_access(
                cur,
                user_id,
                now.isoweekday(),
                now.strftime("%H:%M"),
            )
            allowed = result["allowed"]
            if allowed is None:
                action = "ERROR"
            else:
                action = "ALLOW" if allowed else "BLOCK"

            print(
                f"{now:%Y-%m-%d %H:%M:%S} | {user_name} | "
                f"{device_name} | {mac} | {action} | {result['reason']}"
            )
    finally:
        conn.close()


if __name__ == "__main__":
    init_database()
    check_devices()
