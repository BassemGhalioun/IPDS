import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import os

def generate_synthetic_data(samples=2000):
    """Génère des données de trafic fictives pour l'entraînement si le dataset est absent."""
    print("[!] Dataset KDDTrain+.txt absent. Génération de données synthétiques...")
    
    # 1: Protocol (6=TCP, 17=UDP, 1=ICMP), 4: Length, 22: Count
    data = []
    for _ in range(samples):
        is_attack = np.random.choice([0, 1], p=[0.85, 0.15])
        if is_attack:
            # Simulation d'une attaque (ex: grand nombre de petits paquets)
            proto = np.random.choice([6, 17])
            length = np.random.randint(20, 100)
            count = np.random.randint(100, 500)
        else:
            # Trafic normal
            proto = np.random.choice([6, 17, 1])
            length = np.random.randint(60, 1500)
            count = np.random.randint(1, 40)
        
        data.append([proto, length, count, is_attack])
    
    return pd.DataFrame(data, columns=[1, 4, 22, 41])

def train_idps_ia(file_path):
    if os.path.exists(file_path):
        print(f"[*] Chargement du dataset réel : {file_path}")
        cols = [1, 4, 22] 
        df = pd.read_csv(file_path, header=None)
        X = df[cols].copy()
        y = df[41].apply(lambda x: 0 if x == 'normal' else 1)
        # Conversion des protocoles en numérique
        X[1] = X[1].map({'tcp': 6, 'udp': 17, 'icmp': 1}).fillna(0)
    else:
        df = generate_synthetic_data()
        X = df[[1, 4, 22]]
        y = df[41]

    print("[*] Entraînement du modèle de détection...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_scaled, y)

    # Sauvegarde des artefacts pour le moteur main.py
    joblib.dump(model, "ids_model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    print("[OK] Intelligence Artificielle initialisée avec succès.")

if __name__ == "__main__":
    train_idps_ia("KDDTrain+.txt")