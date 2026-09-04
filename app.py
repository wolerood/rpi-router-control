from flask import Flask, jsonify, request
from database import get_connection
from datetime import datetime
import subprocess

app = Flask(__name__)


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

@app.route("/users", methods=["POST"])
def add_user():

    data = request.get_json()

    if not data or "name" not in data:
        return jsonify({"error": "name required"}), 400

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO users (name) VALUES (?)",
        (data["name"],)
    )

    conn.commit()

    user_id = cur.lastrowid

    conn.close()

    return jsonify({
        "id": user_id,
        "name": data["name"]
    })

@app.route("/devices", methods=["POST"])
def add_device():

    data = request.get_json()

    required = ["user_id", "mac", "name"]

    if not data or not all(x in data for x in required):
        return jsonify({
            "error": "user_id, mac and name required"
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO devices
        (user_id, mac, name)
        VALUES (?, ?, ?)
    """, (
        data["user_id"],
        data["mac"].lower(),
        data["name"]
    ))

    conn.commit()

    device_id = cur.lastrowid

    conn.close()

    return jsonify({
        "id": device_id,
        "user_id": data["user_id"],
        "mac": data["mac"],
        "name": data["name"]
    })

@app.route("/schedules")
def schedules():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            schedules.id,
            users.name,
            schedules.weekday,
            schedules.start_time,
            schedules.end_time
        FROM schedules
        JOIN users
        ON schedules.user_id = users.id
        ORDER BY users.id, schedules.weekday
    """)

    result = []

    for row in cur.fetchall():
        result.append({
            "id": row[0],
            "user": row[1],
            "weekday": row[2],
            "start": row[3],
            "end": row[4]
        })

    conn.close()

    return jsonify(result)


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

    conn = get_connection()
    cur = conn.cursor()

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
        data["user_id"],
        data["weekday"],
        data["start"],
        data["end"]
    ))

    conn.commit()

    schedule_id = cur.lastrowid

    conn.close()

    return jsonify({
        "id": schedule_id
    })

@app.route("/access/<int:user_id>")
def check_access(user_id):

    now = datetime.now()

    weekday = now.isoweekday()
    current_time = now.strftime("%H:%M")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT name, access_mode
        FROM users
        WHERE id = ?
    """, (user_id,))

    user = cur.fetchone()

    if not user:
        conn.close()
        return jsonify({
            "error": "user not found"
        }), 404

    user_name = user[0]
    access_mode = user[1]

    if access_mode == "always_allow":
        conn.close()

        return jsonify({
            "user": user_name,
            "access_mode": access_mode,
            "allowed": True,
            "reason": "manual allow",
            "time": current_time,
            "weekday": weekday
        })

    if access_mode == "always_block":
        conn.close()

        return jsonify({
            "user": user_name,
            "access_mode": access_mode,
            "allowed": False,
            "reason": "manual block",
            "time": current_time,
            "weekday": weekday
        })

    if access_mode != "schedule":
        conn.close()

        return jsonify({
            "error": "invalid access_mode",
            "access_mode": access_mode
        }), 500

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

    conn.close()

    for start_time, end_time in schedules:
        if start_time <= current_time <= end_time:
            return jsonify({
                "user": user_name,
                "access_mode": access_mode,
                "allowed": True,
                "reason": f"{start_time}-{end_time}",
                "time": current_time,
                "weekday": weekday
            })

    return jsonify({
        "user": user_name,
        "access_mode": access_mode,
        "allowed": False,
        "reason": "outside schedule",
        "time": current_time,
        "weekday": weekday
    })

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

app.run(host="0.0.0.0", port=8080)
