from database import get_connection
from firewall import block_mac, get_blocked_macs
from access_policy import normalize_mac


def get_last_blocked_macs(cur):
    """Return registered devices whose last successfully recorded action was BLOCK."""
    cur.execute(
        """
        SELECT d.mac
        FROM devices d
        JOIN device_state s ON lower(s.mac) = lower(d.mac)
        WHERE s.action = 'BLOCK'
        ORDER BY d.id
        """
    )
    return {normalize_mac(row[0]) for row in cur.fetchall()}


def restore_firewall():
    """Restore the last applied blocking state after nftables is recreated."""
    conn = get_connection()
    try:
        desired_blocked = get_last_blocked_macs(conn.cursor())
    finally:
        conn.close()

    actual_blocked = get_blocked_macs()
    restored = 0

    for mac in sorted(desired_blocked - actual_blocked):
        block_mac(mac)
        restored += 1

    return restored


if __name__ == "__main__":
    count = restore_firewall()
    print(f"Restored blocked MAC addresses: {count}")
