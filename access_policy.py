import re


VALID_ACCESS_MODES = (
    "schedule",
    "always_allow",
    "always_block",
)

_MAC_RE = re.compile(r"^[0-9a-f]{12}$")
_TIME_RE = re.compile(r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")


def normalize_mac(value):
    """Return a MAC address in canonical lower-case colon notation."""
    if not isinstance(value, str):
        raise ValueError("mac must be a string")

    compact = value.strip().lower()
    for separator in (":", "-", "."):
        compact = compact.replace(separator, "")

    if not _MAC_RE.fullmatch(compact):
        raise ValueError("mac must contain exactly 12 hexadecimal digits")

    if compact in {"000000000000", "ffffffffffff"}:
        raise ValueError("mac must identify an individual device")

    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def is_valid_time(value):
    return isinstance(value, str) and _TIME_RE.fullmatch(value) is not None


def evaluate_access(access_mode, schedules, weekday, current_time):
    """Evaluate an access policy without touching the database or firewall.

    ``schedules`` contains ``(weekday, start_time, end_time)`` tuples. Weekdays
    use ISO numbering: Monday is 1 and Sunday is 7.
    """
    if access_mode == "always_allow":
        return True, "manual allow"

    if access_mode == "always_block":
        return False, "manual block"

    if access_mode != "schedule":
        return None, f"invalid access_mode: {access_mode}"

    if not isinstance(weekday, int) or not 1 <= weekday <= 7:
        return None, f"invalid weekday: {weekday}"

    if not is_valid_time(current_time):
        return None, f"invalid current_time: {current_time}"

    previous_weekday = 7 if weekday == 1 else weekday - 1

    for schedule_weekday, start_time, end_time in schedules:
        if not (
            isinstance(schedule_weekday, int)
            and 1 <= schedule_weekday <= 7
            and is_valid_time(start_time)
            and is_valid_time(end_time)
        ):
            return None, "invalid schedule data"

        if schedule_weekday == weekday:
            if start_time <= end_time:
                if start_time <= current_time <= end_time:
                    return True, f"{start_time}-{end_time}"
            elif current_time >= start_time:
                return True, f"{start_time}-{end_time}"

        if (
            schedule_weekday == previous_weekday
            and start_time > end_time
            and current_time <= end_time
        ):
            return True, f"{start_time}-{end_time}"

    return False, "outside schedule"


def check_user_access(cur, user_id, weekday, current_time):
    cur.execute(
        "SELECT name, access_mode FROM users WHERE id = ?",
        (user_id,),
    )
    user = cur.fetchone()

    if user is None:
        return {
            "user": None,
            "access_mode": None,
            "allowed": None,
            "reason": "user not found",
        }

    cur.execute(
        """
        SELECT weekday, start_time, end_time
        FROM schedules
        WHERE user_id = ?
        ORDER BY weekday, start_time, end_time
        """,
        (user_id,),
    )
    schedules = cur.fetchall()
    allowed, reason = evaluate_access(
        user[1],
        schedules,
        weekday,
        current_time,
    )

    return {
        "user": user[0],
        "access_mode": user[1],
        "allowed": allowed,
        "reason": reason,
    }
