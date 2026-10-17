from flask import Flask, jsonify, request
from access_policy import (
    VALID_ACCESS_MODES,
    check_user_access,
    is_valid_time,
    normalize_mac,
)
from database import get_connection, init_database
from firewall import FirewallError, allow_mac, get_blocked_macs
from datetime import datetime
import sqlite3
import subprocess
import os
import secrets

app = Flask(__name__)
API_VERSION = 2
app.config["API_TOKEN"] = os.environ.get("RPI_ROUTER_API_TOKEN", "")


@app.before_request
def require_write_token():
    if request.method not in {"POST", "PATCH", "DELETE"}:
        return None

    expected_token = app.config.get("API_TOKEN", "")
    if not expected_token:
        return jsonify({"error": "API write token is not configured"}), 503

    supplied_token = request.headers.get("X-API-Token", "")
    if not supplied_token or not secrets.compare_digest(
        supplied_token,
        expected_token,
    ):
        return jsonify({"error": "invalid or missing API token"}), 401

    return None


@app.route("/status")
def status():
    """Report whether the API, database and firewall control path are usable."""
    checked_at = datetime.now().astimezone().isoformat(timespec="seconds")

    try:
        conn = get_connection()
        try:
            schema_version = conn.execute("PRAGMA user_version").fetchone()[0]
            user_count = conn.execute("SELECT count(*) FROM users").fetchone()[0]
            device_count = conn.execute("SELECT count(*) FROM devices").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error as error:
        return jsonify({
            "status": "unavailable",
            "api_version": API_VERSION,
            "checked_at": checked_at,
            "database": {"ok": False, "error": str(error)},
            "firewall": {"ok": None},
        }), 503

    try:
        blocked_macs = get_blocked_macs()
    except (FirewallError, ValueError) as error:
        return jsonify({
            "status": "degraded",
            "api_version": API_VERSION,
            "checked_at": checked_at,
            "database": {
                "ok": True,
                "schema_version": schema_version,
                "users": user_count,
                "devices": device_count,
            },
            "firewall": {"ok": False, "error": str(error)},
        }), 503

    return jsonify({
        "status": "ok",
        "api_version": API_VERSION,
        "write_auth": "token",
        "checked_at": checked_at,
        "database": {
            "ok": True,
            "schema_version": schema_version,
            "users": user_count,
            "devices": device_count,
        },
        "firewall": {
            "ok": True,
            "blocked_devices": len(blocked_macs),
        },
    })


def get_dhcp_clients():
    clients = []

    try:
        with open("/var/lib/NetworkManager/dnsmasq-wlan0.leases") as f:
            for line in f:
                parts = line.split()

                if len(parts) >= 4:
                    clients.append({
                        "mac": parts[1],
                        "ip": parts[2],
                        "name": parts[3]
                    })

    except Exception as e:
        return []

    return clients

def get_wifi_clients():
    clients = set()

    try:
        result = subprocess.check_output(
            ["iw", "dev", "wlan0", "station", "dump"],
            text=True
        )

        for line in result.splitlines():
            if line.startswith("Station"):
                mac = line.split()[1]
                clients.add(mac.lower())

    except Exception:
        pass

    return clients

@app.route("/clients")
def clients():

    dhcp = get_dhcp_clients()
    wifi = get_wifi_clients()

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT devices.mac, devices.name, users.name
        FROM devices
        LEFT JOIN users
        ON devices.user_id = users.id
    """)

    device_map = {}

    for row in cur.fetchall():
        device_map[row[0].lower()] = {
            "device_name": row[1],
            "owner": row[2]
        }

    conn.close()

    for client in dhcp:
        mac = client["mac"].lower()

        client["online"] = mac in wifi

        if mac in device_map:
            client["device_name"] = device_map[mac]["device_name"]
            client["owner"] = device_map[mac]["owner"]
        else:
            client["device_name"] = client["name"]
            client["owner"] = None

    return jsonify(dhcp)


@app.route("/users")
def users():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
       " SELECT id, name, access_mode FROM users"
    )

    result = []

    for row in cur.fetchall():
        result.append({
            "id": row[0],
            "name": row[1],
	    "access_mode": row[2]	        
   	 })

    conn.close()

    return jsonify(result)

# добавление пользователя
@app.route("/users", methods=["POST"])
def add_user():

    data = request.get_json()

    if not data or "name" not in data:
        return jsonify({"error": "name required"}), 400

    name = data["name"]

    if not isinstance(name, str) or not name.strip():
        return jsonify({
            "error": "name must be non-empty string"
        }), 400

    name = name.strip()
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO users (name) VALUES (?)",
        (name,)
    )

    conn.commit()

    user_id = cur.lastrowid

    conn.close()

    return jsonify({
        "id": user_id,
        "name": name
    })

# переименование пользователя
@app.route("/users/<int:user_id>", methods=["PATCH"])
def update_user(user_id):

    data = request.get_json()

    if not data or "name" not in data:
        return jsonify({
            "error": "name required"
        }), 400

    name = data["name"]

    if not isinstance(name, str) or not name.strip():
        return jsonify({
            "error": "name must be non-empty string"
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id
        FROM users
        WHERE id = ?
    """, (user_id,))

    if not cur.fetchone():
        conn.close()

        return jsonify({
            "error": "user not found"
        }), 404

    cur.execute("""
        UPDATE users
        SET name = ?
        WHERE id = ?
    """, (
        name.strip(),
        user_id
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "id": user_id,
        "name": name.strip()
    })

# изменение доступа пользователя
@app.route("/users/<int:user_id>/access_mode", methods=["PATCH"])
def update_access_mode(user_id):

    data = request.get_json()

    if not data or "access_mode" not in data:
        return jsonify({
            "error": "access_mode required"
        }), 400

    access_mode = data["access_mode"]

    allowed_modes = list(VALID_ACCESS_MODES)

    if access_mode not in allowed_modes:
        return jsonify({
            "error": "invalid access_mode",
            "allowed_values": allowed_modes
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id
        FROM users
        WHERE id = ?
    """, (user_id,))

    if not cur.fetchone():
        conn.close()

        return jsonify({
            "error": "user not found"
        }), 404

    cur.execute("""
        UPDATE users
        SET access_mode = ?
        WHERE id = ?
    """, (
        access_mode,
        user_id
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "user_id": user_id,
        "access_mode": access_mode
    })

# удаление пользователя
@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id
        FROM users
        WHERE id = ?
    """, (user_id,))

    if not cur.fetchone():
        conn.close()

        return jsonify({
            "error": "user not found"
        }), 404

    cur.execute("""
        SELECT COUNT(*)
        FROM devices
        WHERE user_id = ?
    """, (user_id,))

    device_count = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM schedules
        WHERE user_id = ?
    """, (user_id,))

    schedule_count = cur.fetchone()[0]

    if device_count > 0 or schedule_count > 0:
        conn.close()

        return jsonify({
            "error": "user has related records",
            "devices": device_count,
            "schedules": schedule_count
        }), 409

    cur.execute("""
        DELETE FROM users
        WHERE id = ?
    """, (user_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "deleted": True,
        "user_id": user_id
    })

@app.route("/devices", methods=["POST"])
def add_device():

    data = request.get_json()

    required = [
        "user_id",
        "mac",
        "name"
    ]

    if not data or not all(x in data for x in required):
        return jsonify({
            "error": "missing fields"
        }), 400

    user_id = data["user_id"]
    mac = data["mac"]
    name = data["name"]

    if not isinstance(user_id, int):
        return jsonify({
            "error": "user_id must be integer"
        }), 400

    try:
        mac = normalize_mac(mac)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    if not isinstance(name, str) or not name.strip():
        return jsonify({
            "error": "name must be non-empty string"
        }), 400

    name = name.strip()

    conn = get_connection()
    cur = conn.cursor()

    # Проверяем, существует ли пользователь
    cur.execute("""
        SELECT id
        FROM users
        WHERE id = ?
    """, (user_id,))

    if not cur.fetchone():
        conn.close()

        return jsonify({
            "error": "user not found"
        }), 404

    # Добавляем устройство
    try:
        cur.execute("""
            INSERT INTO devices
            (
                user_id,
                mac,
                name
            )
            VALUES (?, ?, ?)
        """,
        (
            user_id,
            mac,
            name
        ))

        conn.commit()

    except sqlite3.IntegrityError:
        conn.close()

        return jsonify({
            "error": "device with this MAC already exists"
        }), 409

    device_id = cur.lastrowid

    conn.close()

    return jsonify({
        "id": device_id,
        "user_id": user_id,
        "mac": mac,
        "name": name
    })

@app.route("/devices", methods=["GET"])
def get_devices():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            d.id,
            d.user_id,
            d.mac,
            d.name,
            u.name
        FROM devices d
        LEFT JOIN users u
            ON d.user_id = u.id
        ORDER BY d.id
    """)

    rows = cur.fetchall()

    conn.close()

    devices = []

    for row in rows:
        devices.append({
            "id": row[0],
            "user_id": row[1],
            "mac": row[2],
            "name": row[3],
            "user": row[4]
        })

    return jsonify(devices)


@app.route("/devices/state", methods=["GET"])
def get_device_states():
    """Return observed firewall state alongside the last policy decision."""
    try:
        blocked_macs = get_blocked_macs()
    except FirewallError as error:
        return jsonify({
            "error": "cannot read firewall state",
            "detail": str(error)
        }), 503

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT
            d.id,
            d.user_id,
            d.mac,
            d.name,
            u.name,
            s.action,
            s.reason,
            s.timestamp
        FROM devices d
        LEFT JOIN users u ON d.user_id = u.id
        LEFT JOIN device_state s ON lower(s.mac) = lower(d.mac)
        ORDER BY d.id
    """)
    rows = cur.fetchall()
    conn.close()

    result = []
    for row in rows:
        try:
            mac = normalize_mac(row[2])
            actual_action = "BLOCK" if mac in blocked_macs else "ALLOW"
            error = None
        except ValueError as validation_error:
            mac = row[2]
            actual_action = None
            error = str(validation_error)

        result.append({
            "id": row[0],
            "user_id": row[1],
            "mac": mac,
            "name": row[3],
            "user": row[4],
            "actual_action": actual_action,
            "last_decision": row[5],
            "reason": row[6],
            "updated_at": row[7],
            "in_sync": row[5] == actual_action if actual_action else False,
            "error": error,
        })

    return jsonify(result)

# изменение устройства 
@app.route("/devices/<int:device_id>", methods=["PATCH"])
def update_device(device_id):

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "no data provided"
        }), 400

    allowed_fields = {
        "name",
        "user_id"
    }

    if not any(field in data for field in allowed_fields):
        return jsonify({
            "error": "nothing to update"
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id
        FROM devices
        WHERE id = ?
    """, (device_id,))

    if not cur.fetchone():
        conn.close()

        return jsonify({
            "error": "device not found"
        }), 404

    if "user_id" in data:

        user_id = data["user_id"]

        if not isinstance(user_id, int):
            conn.close()

            return jsonify({
                "error": "user_id must be integer"
            }), 400

        cur.execute("""
            SELECT id
            FROM users
            WHERE id = ?
        """, (user_id,))

        if not cur.fetchone():
            conn.close()

            return jsonify({
                "error": "user not found"
            }), 404

    fields = []
    values = []

    if "name" in data:

        name = data["name"]

        if not isinstance(name, str) or not name.strip():
            conn.close()

            return jsonify({
                "error": "name must be non-empty string"
            }), 400

        fields.append("name = ?")
        values.append(name.strip())

    if "user_id" in data:
        fields.append("user_id = ?")
        values.append(data["user_id"])

    values.append(device_id)

    cur.execute(
        f"""
        UPDATE devices
        SET {", ".join(fields)}
        WHERE id = ?
        """,
        values
    )

    conn.commit()

    cur.execute("""
        SELECT
            d.id,
            d.user_id,
            d.mac,
            d.name,
            u.name
        FROM devices d
        LEFT JOIN users u
            ON d.user_id = u.id
        WHERE d.id = ?
    """, (device_id,))

    row = cur.fetchone()

    conn.close()

    return jsonify({
        "id": row[0],
        "user_id": row[1],
        "mac": row[2],
        "name": row[3],
        "user": row[4]
    })

# удаление устройства
@app.route("/devices/<int:device_id>", methods=["DELETE"])
def delete_device(device_id):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, mac, name
        FROM devices
        WHERE id = ?
    """, (device_id,))

    device = cur.fetchone()

    if not device:
        conn.close()

        return jsonify({
            "error": "device not found"
        }), 404

    mac = normalize_mac(device[1])

    try:
        blocked_macs = get_blocked_macs()
    except FirewallError as error:
        conn.close()
        return jsonify({
            "error": "cannot read firewall state",
            "detail": str(error)
        }), 503

    try:
        cur.execute("DELETE FROM device_state WHERE mac = ?", (mac,))
        cur.execute("DELETE FROM devices WHERE id = ?", (device_id,))

        if mac in blocked_macs:
            allow_mac(mac)

        conn.commit()
    except (sqlite3.Error, FirewallError) as error:
        conn.rollback()
        conn.close()
        return jsonify({
            "error": "cannot delete device safely",
            "detail": str(error)
        }), 503

    conn.close()

    return jsonify({
        "deleted": True,
        "device_id": device_id,
        "mac": mac,
        "name": device[2]
    })

@app.route("/schedules", methods=["GET"])
def get_schedules():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            s.id,
            s.user_id,
            u.name,
            s.weekday,
            s.start_time,
            s.end_time
        FROM schedules s
        LEFT JOIN users u
            ON s.user_id = u.id
        ORDER BY
            s.user_id,
            s.weekday,
            s.start_time
    """)

    rows = cur.fetchall()

    conn.close()

    schedules = []

    for row in rows:
        schedules.append({
            "id": row[0],
            "user_id": row[1],
            "user": row[2],
            "weekday": row[3],
            "start": row[4],
            "end": row[5]
        })

    return jsonify(schedules)

# добавление расписания
@app.route("/schedules", methods=["POST"])
def add_schedule():

    data = request.get_json()

    required = [
        "user_id",
        "weekday",
        "start",
        "end"
    ]

    if not data or not all(x in data for x in required):
        return jsonify({
            "error": "missing fields"
        }), 400

    user_id = data["user_id"]
    weekday = data["weekday"]
    start = data["start"]
    end = data["end"]

    if not isinstance(user_id, int):
        return jsonify({
            "error": "user_id must be integer"
        }), 400

    if not isinstance(weekday, int) or not 1 <= weekday <= 7:
        return jsonify({
            "error": "weekday must be integer from 1 to 7"
        }), 400

    if not is_valid_time(start) or not is_valid_time(end):
        return jsonify({
            "error": "start and end must be in HH:MM format"
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id
        FROM users
        WHERE id = ?
    """, (user_id,))

    if not cur.fetchone():
        conn.close()

        return jsonify({
            "error": "user not found"
        }), 404

    cur.execute("""
        INSERT INTO schedules
        (
            user_id,
            weekday,
            start_time,
            end_time
        )
        VALUES (?, ?, ?, ?)
    """,
    (
        user_id,
        weekday,
        start,
        end
    ))

    conn.commit()

    schedule_id = cur.lastrowid

    conn.close()

    return jsonify({
        "id": schedule_id,
        "user_id": user_id,
        "weekday": weekday,
        "start": start,
        "end": end
    })

# изменение расписания
@app.route("/schedules/<int:schedule_id>", methods=["PATCH"])
def update_schedule(schedule_id):

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "no data provided"
        }), 400

    allowed_fields = {
        "user_id",
        "weekday",
        "start",
        "end"
    }

    if not any(field in data for field in allowed_fields):
        return jsonify({
            "error": "nothing to update"
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id
        FROM schedules
        WHERE id = ?
    """, (schedule_id,))

    if not cur.fetchone():
        conn.close()

        return jsonify({
            "error": "schedule not found"
        }), 404

    fields = []
    values = []

    if "user_id" in data:
        user_id = data["user_id"]

        if not isinstance(user_id, int):
            conn.close()

            return jsonify({
                "error": "user_id must be integer"
            }), 400

        cur.execute("""
            SELECT id
            FROM users
            WHERE id = ?
        """, (user_id,))

        if not cur.fetchone():
            conn.close()

            return jsonify({
                "error": "user not found"
            }), 404

        fields.append("user_id = ?")
        values.append(user_id)

    if "weekday" in data:
        weekday = data["weekday"]

        if not isinstance(weekday, int) or not 1 <= weekday <= 7:
            conn.close()

            return jsonify({
                "error": "weekday must be integer from 1 to 7"
            }), 400

        fields.append("weekday = ?")
        values.append(weekday)

    if "start" in data:
        start = data["start"]

        if not is_valid_time(start):
            conn.close()

            return jsonify({
                "error": "start must be in HH:MM format"
            }), 400

        fields.append("start_time = ?")
        values.append(start)

    if "end" in data:
        end = data["end"]

        if not is_valid_time(end):
            conn.close()

            return jsonify({
                "error": "end must be in HH:MM format"
            }), 400

        fields.append("end_time = ?")
        values.append(end)

    values.append(schedule_id)

    cur.execute(
        f"""
        UPDATE schedules
        SET {", ".join(fields)}
        WHERE id = ?
        """,
        values
    )

    conn.commit()

    cur.execute("""
        SELECT
            s.id,
            s.user_id,
            u.name,
            s.weekday,
            s.start_time,
            s.end_time
        FROM schedules s
        LEFT JOIN users u
            ON s.user_id = u.id
        WHERE s.id = ?
    """, (schedule_id,))

    row = cur.fetchone()

    conn.close()

    return jsonify({
        "id": row[0],
        "user_id": row[1],
        "user": row[2],
        "weekday": row[3],
        "start": row[4],
        "end": row[5]
    })

# удаление расписания
@app.route("/schedules/<int:schedule_id>", methods=["DELETE"])
def delete_schedule(schedule_id):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            user_id,
            weekday,
            start_time,
            end_time
        FROM schedules
        WHERE id = ?
    """, (schedule_id,))

    schedule = cur.fetchone()

    if not schedule:
        conn.close()

        return jsonify({
            "error": "schedule not found"
        }), 404

    cur.execute("""
        DELETE FROM schedules
        WHERE id = ?
    """, (schedule_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "deleted": True,
        "schedule_id": schedule_id,
        "user_id": schedule[1],
        "weekday": schedule[2],
        "start": schedule[3],
        "end": schedule[4]
    })

@app.route("/access/<int:user_id>")
def check_access(user_id):
    now = datetime.now()
    weekday = now.isoweekday()
    current_time = now.strftime("%H:%M")
    conn = get_connection()
    try:
        result = check_user_access(
            conn.cursor(),
            user_id,
            weekday,
            current_time,
        )
    finally:
        conn.close()

    if result["user"] is None:
        return jsonify({"error": "user not found"}), 404

    if result["allowed"] is None:
        return jsonify({
            "error": result["reason"],
            "access_mode": result["access_mode"]
        }), 500

    result["time"] = current_time
    result["weekday"] = weekday
    return jsonify(result)

@app.route("/logs")
def logs():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            timestamp,
            user_name,
            device_name,
            device_mac,
            action,
            reason
        FROM access_log
        ORDER BY id DESC
        LIMIT 50
    """)

    result = []

    for row in cur.fetchall():
        result.append({
            "time": row[0],
            "user": row[1],
            "device": row[2],
            "mac": row[3],
            "action": row[4],
            "reason": row[5]
        })

    conn.close()

    return jsonify(result) 

if __name__ == "__main__":
    init_database()
    app.run(host="0.0.0.0", port=8080)
