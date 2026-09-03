import sqlite3
from datetime import datetime


DB_PATH = "/home/pi/rpi-router-api/router.db"


def check_access(user_id):

    now = datetime.now()
    weekday = now.isoweekday()
    current_time = now.strftime("%H:%M")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT name, access_mode
        FROM users
        WHERE id = ?
    """, (user_id,))

    user = cur.fetchone()

    if not user:
        conn.close()
        return False, "user not found"

    user_name = user[0]
    access_mode = user[1]

    if access_mode == "always_allow":
        conn.close()
        return True, "manual allow"

    if access_mode == "always_block":
        conn.close()
        return False, "manual block"

    cur.execute("""
        SELECT start_time, end_time
        FROM schedules
        WHERE user_id = ?
        AND weekday = ?
    """,
    (
        user_id,
        weekday
    ))

    schedules = cur.fetchall()

    conn.close()

    for item in schedules:
        if item[0] <= current_time <= item[1]:
            return True, f"{item[0]}-{item[1]}"

    return False, "outside schedule"


def check_devices():

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT
            devices.name,
            devices.mac,
            users.name,
            users.id
        FROM devices
        JOIN users
        ON devices.user_id = users.id
    """)

    devices = cur.fetchall()

    conn.close()

    for device in devices:

        allowed, reason = check_access(device[3])

        action = "ALLOW" if allowed else "BLOCK"

        print(
            f"{datetime.now()} | "
            f"{device[2]} | "
            f"{device[0]} | "
            f"{device[1]} | "
            f"{action} | "
            f"{reason}"
        )


if __name__ == "__main__":
    check_devices()
