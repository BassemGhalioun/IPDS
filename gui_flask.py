
from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for
import threading
import main
import auth
import csv
import io
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "IDPS_SECRET_ULTRA_SECURE"

# Initialisation de la base de données utilisateurs au démarrage
auth.init_db()

# --- MIDDLEWARE AUTH ---
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_view'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route("/login", methods=["GET", "POST"])
def login_view():
    if request.method == "POST":
        user = auth.check_user(request.form.get("username"), request.form.get("password"))
        if user:
            session['user'] = user
            return redirect(url_for('index'))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login_view'))

@app.route("/")
@login_required
def index():
    return render_template("index.html", user=session['user'])

# --- API DATA ---
@app.route("/api/status")
@login_required
def get_status():
    return jsonify({
        "stats": {
            "total_packets": main.packet_counter,
            "total_alerts": len(main.ALERTS),
            "blocked_ips": len(main.blacklist.get_all())
        },
        "alerts": list(main.ALERTS),
        "packets": list(main.RECENT_PACKETS),
        "blacklist": main.blacklist.get_all(),
        "interface": main.IFACE
    })

# --- GESTION BLACKLIST ---
@app.route("/api/block", methods=["POST"])
@login_required
def block_ip():
    ip = request.json.get("ip")
    if ip:
        main.blacklist.add_ip(ip)
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

@app.route("/api/unblock/<ip>", methods=["POST"])
@login_required
def unblock_ip(ip):
    success = main.blacklist.remove_ip(ip)
    return jsonify({"status": "success" if success else "error"})

# --- GESTION UTILISATEURS ---
@app.route("/api/users")
@login_required
def list_users():
    return jsonify(auth.get_all_users())

@app.route("/api/users/add", methods=["POST"])
@login_required
def add_user():
    data = request.json
    success = auth.create_user(data['username'], data['password'], data['role'])
    return jsonify({"status": "success" if success else "error"})

@app.route("/api/users/delete/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    auth.delete_user(user_id)
    return jsonify({"status": "success"})

# --- EXPORT LOGS ---
@app.route("/api/logs/export")
@login_required
def export_logs():
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["Type", "Source", "Destination", "Details", "Date"])
    for alert in main.ALERTS:
        cw.writerow([alert['type'], alert['src_ip'], alert['dst_ip'], alert['details'], datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype="text/csv", as_attachment=True, download_name="idps_alerts.csv")

def start_sniffer_thread():
    t = threading.Thread(
        target=main.start_sniff,
        args=(main.IFACE, main.handle_packet, main.BPF_FILTER),
        daemon=True
    )
    t.start()

if __name__ == "__main__":
    print("[*] Lancement du moteur IDPS...")
    start_sniffer_thread()
    app.run(host="0.0.0.0", port=5000, debug=False)
