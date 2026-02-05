
import threading
import subprocess
from pathlib import Path

# Nom du fichier où sont stockées les IPs bannies
BLACKLIST_FILE = "blacklist.txt"

class BlacklistManager:
    def __init__(self):
        """Initialise le gestionnaire de liste noire dynamique."""
        self._lock = threading.Lock()
        self._blacklist = set()
        self._load_from_file()

    def _load_from_file(self):
        """Charge les IPs bannies depuis le fichier texte au démarrage."""
        path = Path(BLACKLIST_FILE)
        if path.exists():
            with path.open("r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        self._blacklist.add(ip)
            print(f"[SYSTEM] {len(self._blacklist)} IPs chargées depuis la blacklist.")

    def _save_to_file(self):
        """Sauvegarde la liste actuelle dans le fichier texte."""
        path = Path(BLACKLIST_FILE)
        with path.open("w") as f:
            for ip in sorted(self._blacklist):
                f.write(ip + "\n")

    def _iptables_block_ip(self, ip):
        """Bloque dynamiquement une IP via iptables."""
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            print(f"[IPTABLES] BLOCK : {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[IPTABLES] Erreur blocage {ip}: {e.stderr.decode().strip()}")

    def _iptables_unblock_ip(self, ip):
        """Débloque dynamiquement une IP via iptables."""
        try:
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            print(f"[IPTABLES] UNBLOCK : {ip}")
        except subprocess.CalledProcessError as e:
            pass

    def add_ip(self, ip):
        """Ajoute une IP détectée comme malveillante à la blacklist."""
        if not ip or ip == "127.0.0.1": return False
        
        with self._lock:
            if ip not in self._blacklist:
                self._blacklist.add(ip)
                self._save_to_file()
                self._iptables_block_ip(ip)
                return True
        return False

    def remove_ip(self, ip):
        """Supprime une IP de la blacklist."""
        if not ip: return False
        with self._lock:
            if ip in self._blacklist:
                self._blacklist.remove(ip)
                self._save_to_file()
                self._iptables_unblock_ip(ip)
                return True
        return False

    def is_blocked(self, ip):
        with self._lock:
            return ip in self._blacklist

    def get_all(self):
        with self._lock:
            return list(self._blacklist)
