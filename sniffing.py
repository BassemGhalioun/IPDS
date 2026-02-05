
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, conf

def extract_features(pkt):
    """Extraction robuste des données du paquet."""
    features = {
        "src_ip": None, "dst_ip": None,
        "src_mac": pkt[Ether].src if Ether in pkt else None,
        "dst_mac": pkt[Ether].dst if Ether in pkt else None,
        "src_port": None, "dst_port": None,
        "protocol": "OTHER", "tcp_flags": None,
        "arp_op": None, "length": len(pkt),
        "timestamp": None
    }

    if IP in pkt:
        features["src_ip"] = pkt[IP].src
        features["dst_ip"] = pkt[IP].dst
        features["protocol"] = "TCP" if pkt[IP].proto == 6 else "UDP" if pkt[IP].proto == 17 else "ICMP" if pkt[IP].proto == 1 else "IP"
        if TCP in pkt:
            features["src_port"] = pkt[TCP].sport
            features["dst_port"] = pkt[TCP].dport
            features["tcp_flags"] = int(pkt[TCP].flags)
        elif UDP in pkt:
            features["src_port"] = pkt[UDP].sport
            features["dst_port"] = pkt[UDP].dport
            
    elif ARP in pkt:
        features["protocol"] = "ARP"
        features["src_ip"] = pkt[ARP].psrc
        features["dst_ip"] = pkt[ARP].pdst
        features["arp_op"] = pkt[ARP].op

    return features

def start_sniff(iface, packet_callback, stop_event, bpf_filter=None):
    """Lance la capture en mode Promiscuous."""
    print(f"[*] Démarrage du sniffer sur {iface} (Filtre: {bpf_filter})...")
    
    def _callback_wrapper(pkt):
        if not stop_event.is_set():
            feats = extract_features(pkt)
            packet_callback(pkt, feats)

    try:
        sniff(
            iface=iface,
            prn=_callback_wrapper,
            filter=bpf_filter,
            store=False,
            promisc=True, # FORCER LE MODE PROMISCUOUS
            stop_filter=lambda x: stop_event.is_set()
        )
    except Exception as e:
        print(f"[!] Erreur fatale Scapy: {e}")
