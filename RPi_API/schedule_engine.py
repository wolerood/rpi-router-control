import json
from database import get_connection
import subprocess
from datetime import datetime


DB_PATH = "/home/pi/rpi-router-api/router.db"
LOG_FILE = "/var/log/rpi-router/access.log"

NFT_FAMILY = "inet"
NFT_TABLE = "parental_control"
NFT_SET = "blocked_macs"


def write_log(message):

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")


def run_nft(args):
    result = subprocess.run(
        ["nft"] + args,
        capture_output=True,
        text=True
    )

    return result.returncode, result.stdout, result.stderr.strip()


def get_blocked_macs():
    """
    Возвращает текущее содержимое nftables set blocked_macs.
    """

    code, stdout, stderr = run_nft([
        "-j",
        "list",
        "set",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_SET
    ])

    if code != 0:
        raise RuntimeError(
            f"cannot read nftables set: {stderr}"
        )

    data = json.loads(stdout)

    blocked = set()

    for item in data.get("nftables", []):
        set_data = item.get("set")

        if not set_data:
            continue

        elements = set_data.get("elem", [])

        for element in elements:
            if isinstance(element, str):
                blocked.add(element.lower())

    return blocked


def nft_block(mac):
    code, stdout, stderr = run_nft([
        "add",
        "element",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_SET,
        "{",
        mac,
        "}"
    ])

    if code != 0:
        return False, stderr

    return True, None


def nft_allow(mac):
    code, stdout, stderr = run_nft([
        "delete",
        "element",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_SET,
        "{",
        mac,
        "}"
    ])

    if code != 0:
        return False, stderr

    return True, None


def check_access(cur, user_id, weekday, current_time):

    cur.execute("""
        SELECT access_mode
        FROM users
        WHERE id = ?
    """, (user_id,))

    row = cur.fetchone()

    if not row:
        return None, "user not found"

    access_mode = row[0]

    if access_mode == "always_allow":
        return True, "manual allow"

    if access_mode == "always_block":
        return False, "manual block"

    if access_mode != "schedule":
        return None, f"invalid access_mode: {access_mode}"

    #
    # Расписания, которые начинаются сегодня.
    #
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

        #
        # Обычный интервал, например 07:00-21:00.
        #
        if start_time <= end_time:

            if start_time <= current_time <= end_time:
                return True, f"{start_time}-{end_time}"

        #
        # Ночной интервал, например 22:00-07:00.
        # Здесь проверяется часть ДО полуночи.
        #
        else:

            if current_time >= start_time:
                return True, f"{start_time}-{end_time}"

    #
    # Проверяем ночной интервал, начавшийся вчера.
    #
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

    for start_time, end_time in previous_schedules:

        #
        # Нас интересуют только интервалы,
        # пересекающие полночь.
        #
        if start_time > end_time:

            if current_time <= end_time:
                return True, f"{start_time}-{end_time}"

    return False, "outside schedule"


def main():

    now = datetime.now()
    weekday = now.isoweekday()
    current_time = now.strftime("%H:%M")

    try:
        blocked_macs = get_blocked_macs()

    except Exception as error:
        print(
            f"{now:%Y-%m-%d %H:%M:%S} | "
            f"ERROR | {error}"
        )
        return 1

    conn = get_connection()
    cur = conn.cursor()

    def write_access_log(
        cur,
        mac,
        device_name,
        user_name,
        action,
        reason,
        timestamp
        ):

        cur.execute("""
            INSERT INTO access_log
            (
                device_mac,
                device_name,
                user_name,
                action,
                reason,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            mac,
            device_name,
            user_name,
            action,
            reason,
            timestamp
        ))

    cur.execute("""
        SELECT
            devices.mac,
            devices.name,
            users.id,
            users.name
        FROM devices
        JOIN users
        ON devices.user_id = users.id
    """)

    def get_previous_state(cur, mac):

        cur.execute("""
            SELECT action, reason
            FROM device_state
            WHERE mac = ?
        """, (mac,))

        return cur.fetchone()


    def update_state(
        cur,
        mac,
        device_name,
        user_name,
        action,
        reason,
        timestamp
        ):

            cur.execute("""
                UPDATE device_state
                SET
                    device_name = ?,
                    user_name = ?,
                    action = ?,
                    reason = ?,
                    timestamp = ?
                WHERE mac = ?
            """,
            (
                device_name,
                user_name,
                action,
                reason,
                timestamp,
                mac
            ))

            if cur.rowcount == 0:
                cur.execute("""
                    INSERT INTO device_state
                    (
                        mac,
                        device_name,
                        user_name,
                        action,
                        reason,
                        timestamp
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    mac,
                    device_name,
                    user_name,
                    action,
                    reason,
                    timestamp
                ))


    devices = cur.fetchall()

    exit_code = 0

    for mac, device_name, user_id, user_name in devices:

        mac = mac.lower()

        allowed, reason = check_access(
            cur,
            user_id,
            weekday,
            current_time
        )

        #
        # Некорректные данные.
        # Firewall не изменяем.
        #
        if allowed is None:
            print(
                f"{now:%Y-%m-%d %H:%M:%S} | "
                f"{user_name} | "
                f"{device_name} | "
                f"{mac} | "
                f"ERROR | "
                f"{reason}"
            )

            exit_code = 1
            continue

        #
        # Доступ разрешён.
        #
        if allowed:

            if mac in blocked_macs:

                success, error = nft_allow(mac)

                if not success:
                    print(
                        f"{now:%Y-%m-%d %H:%M:%S} | "
                        f"{user_name} | "
                        f"{device_name} | "
                        f"{mac} | "
                        f"ERROR | "
                        f"cannot remove from blocked_macs: {error}"
                    )

                    exit_code = 1
                    continue

                blocked_macs.remove(mac)

            action = "ALLOW"

        #
        # Доступ запрещён.
        #
        else:

            if mac not in blocked_macs:

                success, error = nft_block(mac)

                if not success:
                    print(
                        f"{now:%Y-%m-%d %H:%M:%S} | "
                        f"{user_name} | "
                        f"{device_name} | "
                        f"{mac} | "
                        f"ERROR | "
                        f"cannot add to blocked_macs: {error}"
                    )

                    exit_code = 1
                    continue

                blocked_macs.add(mac)

            action = "BLOCK"

        message = (
            f"{now:%Y-%m-%d %H:%M:%S} | "
            f"{user_name} | "
            f"{device_name} | "
            f"{mac} | "
            f"{action} | "
            f"{reason}"
        )

        print(message)
        write_log(message)


        previous = get_previous_state(cur, mac)

        if previous is None or previous[0] != action:

            write_access_log(
                cur,
                mac,
                device_name,
                user_name,
                action,
                reason,
                f"{now:%Y-%m-%d %H:%M:%S}"
            )

        if previous is None or previous[0] != action or previous[1] != reason:
            update_state(
                cur,
                mac,
                device_name,
                user_name,
                action,
                reason,
                f"{now:%Y-%m-%d %H:%M:%S}"
            )

        conn.commit()

    conn.close()

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
