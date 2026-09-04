import sqlite3
from datetime import datetime


DB_PATH = "/home/pi/rpi-router-api/router.db"


def check_access(user_id):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    now = datetime.now()
    weekday = now.isoweekday()
    current_time = now.strftime("%H:%M")

    cur.execute("""
        SELECT name, access_mode
        FROM users
        WHERE id = ?
    """, (user_id,))

    user = cur.fetchone()

    if not user:
        conn.close()
        return None, "user not found"

    user_name = user[0]
    access_mode = user[1]

    if access_mode == "always_allow":
        conn.close()
        return True, "manual allow"

    if access_mode == "always_block":
        conn.close()
        return False, "manual block"

    if access_mode != "schedule":
        conn.close()
        return None, f"invalid access_mode: {access_mode}"

    # Расписания, начинающиеся сегодня
    cur.execute("""
        SELECT start_time, end_time
        FROM schedules
        WHERE user_id = ?
        AND weekday = ?
    """, (
        user_id,
        weekday
    ))

    schedules = cur.fetchall()

    for start_time, end_time in schedules:

        # Обычный интервал, например 07:00-21:00
        if start_time <= end_time:

            if start_time <= current_time <= end_time:
                conn.close()
                return True, f"{start_time}-{end_time}"

        # Ночной интервал, например 22:00-07:00
        else:

            # Часть интервала до полуночи
            if current_time >= start_time:
                conn.close()
                return True, f"{start_time}-{end_time}"

    # Проверяем ночной интервал,
    # который начался в предыдущий день
    previous_weekday = 7 if weekday == 1 else weekday - 1

    cur.execute("""
        SELECT start_time, end_time
        FROM schedules
        WHERE user_id = ?
        AND weekday = ?
    """, (
        user_id,
        previous_weekday
    ))

    previous_schedules = cur.fetchall()

    conn.close()

    for start_time, end_time in previous_schedules:

        if start_time > end_time:

            if current_time <= end_time:
                return True, f"{start_time}-{end_time}"

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
