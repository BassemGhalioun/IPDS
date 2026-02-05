
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
import threading
import main
import auth
import io
import csv
import os
import sys
from datetime import datetime
from scapy.all import get_if_list, get_if_addr

if os.getuid() != 0:
    print("\n[!] ERREUR : L'IDPS doit être lancé avec SUDO")
    sys.exit(1)

app = Flask(__name__)
app.secret_key = "SENTINEL_IDPS_KEY_2024"

engine_stop_event = threading.Event()
engine_stop_event.set() 

auth.init_db()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = auth.check_user(request.form.get('username'), request.form.get('password'))
        if user:
            session['user'] = user
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('index.html', user=session['user'])

@app.route('/api/stats')
def get_stats():
    return jsonify({
        "engine_active": not engine_stop_event.is_set(),
        "packets_count": main.packet_counter,
        "threats_count": len(main.ALERTS),
        "blocked_count": len(main.blacklist.get_all()),
        "attack_distribution": main.detector.attack_stats,
        "alerts": list(main.ALERTS),
        "ia_logs": list(main.IA_LOGS),
        "blacklist": main.blacklist.get_all(),
        "ml_ready": main.ia_detector.model is not None
    })

@app.route('/api/ml/train', methods=['POST'])
def train_ml():
    """Déclenche l'apprentissage du modèle."""
    success = main.ia_detector.train()
    return jsonify({"status": "success" if success else "error"})

@app.route('/api/logs/export')
def export_logs():
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["DATE", "TYPE", "SOURCE IP", "DESTINATION IP", "DETAILS"])
    for alert in main.ALERTS:
        cw.writerow([alert['timestamp'], alert['type'], alert['src_ip'], alert['dst_ip'], alert['details']])
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype="text/csv", as_attachment=True, download_name="alerts_idps.csv")

@app.route('/api/blacklist/add', methods=['POST'])
def add_to_blacklist():
    ip = request.json.get('ip')
    if ip:
        main.blacklist.add_ip(ip)
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

@app.route('/api/blacklist/remove/<ip>', methods=['POST'])
def remove_from_blacklist(ip):
    main.blacklist.remove_ip(ip)
    return jsonify({"status": "success"})

@app.route('/api/interfaces')
def get_interfaces():
    interfaces_info = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip != "0.0.0.0": interfaces_info.append({"name": iface, "ip": ip})
        except: continue
    return jsonify({"interfaces": interfaces_info})

@app.route('/api/engine/toggle', methods=['POST'])
def toggle_engine():
    data = request.json or {}
    selected_iface = data.get('interface', main.IFACE)
    if engine_stop_event.is_set():
        engine_stop_event.clear()
        main.IFACE = selected_iface
        t = threading.Thread(target=main.start_sniff, args=(main.IFACE, main.handle_packet, engine_stop_event), daemon=True)
        t.start()
        status = "running"
    else:
        engine_stop_event.set()
        status = "stopped"
    return jsonify({"status": status})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
