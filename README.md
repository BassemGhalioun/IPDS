# 🛡️ CyberGuard IDPS - Suite de Sécurité Réseau

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-JWT_Enabled-red.svg)

CyberGuard est un système hybride de détection et de prévention d'intrusion (IDPS) conçu pour surveiller, analyser et protéger les réseaux locaux en temps réel. Il combine l'analyse par signatures (Scapy) et l'intelligence artificielle (Random Forest).

## ✨ Fonctionnalités

- **🧠 Détection IA** : Modèle Machine Learning (Random Forest) pour détecter les anomalies de trafic (DDoS, Flooding).
- **🔍 Moteur de Signatures** : Identification précise des scans de ports, SYN Floods et ARP Spoofing.
- **🛡️ Prévention Active (IPS)** : Blocage automatique des IPs malveillantes via `iptables`.
- **🔐 Sécurité JWT** : Console d'administration protégée par jetons (Token Auth).
- **📊 SOC Dashboard** : Visualisation en temps réel du trafic, des menaces et de la santé du réseau.
- **📄 Exportation** : Journalisation complète et export des alertes au format CSV.

## 📋 Prérequis

Le projet doit être exécuté sur **Linux** (Debian/Ubuntu, Kali, AlmaLinux) avec les privilèges **ROOT** pour la capture de paquets.

### Dépendances système
```bash
# Ubuntu / Debian / Kali
sudo apt-get update
sudo apt-get install libpcap-dev iptables python3-pip

# RHEL / AlmaLinux
sudo dnf install libpcap-devel iptables
```

## 🚀 Installation & Lancement

1. **Cloner le projet**
   ```bash
   git clone https://github.com/votre-user/cyberguard-idps.git
   cd cyberguard-idps
   ```

2. **Installer les bibliothèques Python**
   ```bash
   sudo pip3 install -r requirements.txt
   ```

3. **Lancer le serveur (ROOT obligatoire)**
   ```bash
   sudo python3 server.py
   ```

4. **Accès Web**
   Ouvrez `http://localhost:5000`
   - **Login** : `admin`
   - **Password** : `admin`

## 🧠 Utilisation de l'IA

Pour activer le moteur IA, rendez-vous dans l'onglet **"Intelligence ML"** et cliquez sur **"Lancer l'apprentissage"**. Le système va générer un modèle d'entraînement basé sur les comportements de trafic. L'IA surveillera ensuite la fréquence et la taille des paquets pour identifier les attaques complexes.

## 📁 Structure du code

- `server.py` : Point d'entrée, API REST et gestion JWT.
- `main.py` : Moteur de corrélation et logique de capture.
- `ml_model.py` : Intelligence Artificielle (Scikit-Learn).
- `sniffing.py` : Extraction de caractéristiques réseau via Scapy.
- `prevention.py` : Interface avec `iptables` pour le bannissement d'IP.
- `auth.py` : Gestion de la base de données SQL et des tokens.

---
*Avertissement : Ce logiciel est destiné à des fins éducatives et de recherche en sécurité. L'utilisation sur un réseau sans autorisation est illégale.*

