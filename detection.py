
import time
from collections import defaultdict

# SEUILS SENSIBLES POUR RÉACTION DYNAMIQUE
TIME_WINDOW = 3            # Fenêtre de 3 secondes
SYN_FLOOD_THRESHOLD = 10   # 10 paquets SYN
PORT_SCAN_THRESHOLD = 5    # 5 ports différents
UDP_FLOOD_THRESHOLD = 20

class DetectionEngine:
    def __init__(self):
        self.syn_history = defaultdict(list)
        self.port_scan_history = defaultdict(set)
        self.arp_table = {} 
        self.last_alert_time = {}
        self.alert_cooldown = 2 
        self.attack_stats = {
            "SYN Flood": 0, "Port Scan": 0, "UDP Flood": 0, "ARP Spoofing": 0, "Anomalie IA": 0
        }

    def _can_alert(self, alert_key):
        now = time.time()
        last = self.last_alert_time.get(alert_key, 0)
        if now - last > self.alert_cooldown:
            self.last_alert_time[alert_key] = now
            return True
        return False

    def detect(self, feats):
        src_ip = feats.get("src_ip")
        dst_ip = feats.get("dst_ip")
        proto = feats.get("protocol")
        now = time.time()

        if not src_ip: return None

        # --- Détection Scan de Ports ---
        if proto == "TCP" and feats.get("dst_port"):
            self.port_scan_history[src_ip].add(feats["dst_port"])
            if len(self.port_scan_history[src_ip]) > PORT_SCAN_THRESHOLD:
                if self._can_alert(("SCAN", src_ip)):
                    self.attack_stats["Port Scan"] += 1
                    # Reset après alerte pour permettre de redétecter
                    self.port_scan_history[src_ip] = set()
                    return {"type": "Port Scan", "src_ip": src_ip, "dst_ip": dst_ip, "details": f"Scan de {len(self.port_scan_history[src_ip])} ports"}

        # --- Détection SYN Flood ---
        if proto == "TCP" and feats.get("tcp_flags") == 2:
            self.syn_history[src_ip].append(now)
            # Nettoyage ancienne historique
            self.syn_history[src_ip] = [t for t in self.syn_history[src_ip] if now - t <= TIME_WINDOW]
            if len(self.syn_history[src_ip]) > SYN_FLOOD_THRESHOLD:
                if self._can_alert(("SYN", src_ip)):
                    self.attack_stats["SYN Flood"] += 1
                    return {"type": "SYN Flood", "src_ip": src_ip, "dst_ip": dst_ip, "details": "Saturation SYN détectée"}

        return None
