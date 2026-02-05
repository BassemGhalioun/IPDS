
from collections import deque, defaultdict
from sniffing import start_sniff
from detection import DetectionEngine
from prevention import BlacklistManager
from ml_model import MLDetector
from logger import log_alert
from datetime import datetime
import time
import traceback

# CONFIG
IFACE = "eth0" 
WHITELIST = ["127.0.0.1", "0.0.0.0"]

# MOTEURS
detector = DetectionEngine()
blacklist = BlacklistManager()
ia_detector = MLDetector()

# DATA
packet_counter = 0
ALERTS = deque(maxlen=500)
IA_LOGS = deque(maxlen=50)
ip_frequency = defaultdict(list) # Pour calculer les paquets/sec par IP

def handle_packet(pkt, feats):
    global packet_counter
    try:
        src_ip = feats.get("src_ip")
        dst_ip = feats.get("dst_ip")
        if not src_ip: return

        packet_counter += 1
        if blacklist.is_blocked(src_ip): return

        # CALCUL FRÉQUENCE (Feature cruciale pour l'IA)
        now = time.time()
        ip_frequency[src_ip].append(now)
        # On ne garde que les paquets des 2 dernières secondes
        ip_frequency[src_ip] = [t for t in ip_frequency[src_ip] if now - t <= 2]
        current_freq = len(ip_frequency[src_ip])

        # MACHINE LEARNING
        is_ia_attack = False
        try:
            pred_class, confidence = ia_detector.predict(feats["protocol"], feats["length"], current_freq)
            
            # Log IA systématique
            IA_LOGS.append({
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "ip": src_ip,
                "proto": feats["protocol"],
                "len": feats["length"],
                "freq": current_freq,
                "result": "ATTACK" if pred_class == 1 else "NORMAL",
                "conf": f"{confidence:.1f}%"
            })

            if pred_class == 1 and src_ip not in WHITELIST and confidence > 80:
                is_ia_attack = True
                alert = {
                    "type": "Anomalie IA",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "details": f"IA: Comportement hostile détecté ({confidence:.1f}% certitude)",
                    "source": "ML Engine"
                }
                process_threat(alert)
        except: pass

        # SIGNATURES (Fallback)
        if not is_ia_attack:
            rule_alert = detector.detect(feats)
            if rule_alert and src_ip not in WHITELIST:
                rule_alert["source"] = "Moteur Signature"
                process_threat(rule_alert)
            
    except Exception as e:
        pass

def process_threat(alert):
    alert['timestamp'] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    ALERTS.append(alert)
    log_alert(alert['type'], alert['src_ip'], alert['dst_ip'], alert['details'])
    
    # Auto-block
    if alert['type'] in ["SYN Flood", "Port Scan", "Anomalie IA"]:
        blacklist.add_ip(alert['src_ip'])
