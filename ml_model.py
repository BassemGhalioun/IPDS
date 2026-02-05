
import joblib
import numpy as np
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

class MLDetector:
    def __init__(self):
        self.model_path = "ids_model.pkl"
        self.scaler_path = "scaler.pkl"
        self.model = None
        self.scaler = None
        self.load()

    def load(self):
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                return True
            except: return False
        return False

    def train(self):
        """Génère un dataset d'entraînement et forge le modèle Random Forest."""
        print("[IA] Début de l'apprentissage...")
        data = []
        # Génération de patterns d'attaques et de trafic normal pour l'apprentissage
        for _ in range(2000):
            is_attack = np.random.choice([0, 1], p=[0.7, 0.3])
            if is_attack:
                proto = np.random.choice([6, 17]) # TCP ou UDP
                length = np.random.randint(20, 120) # Petits paquets suspects
                freq = np.random.randint(100, 1000) # Haute fréquence
            else:
                proto = np.random.choice([1, 6, 17])
                length = np.random.randint(60, 1500)
                freq = np.random.randint(1, 50)
            data.append([proto, length, freq, is_attack])
        
        df = pd.DataFrame(data, columns=['proto', 'len', 'freq', 'label'])
        X = df[['proto', 'len', 'freq']]
        y = df['label']

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_scaled, y)
        
        # Sauvegarde
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        print("[IA] Apprentissage terminé et modèle sauvegardé.")
        return True

    def predict(self, protocol, length, frequency):
        """Analyse un paquet avec les 3 features clés."""
        if not self.model or not self.scaler:
            return 0, 0.0

        proto_num = 6 if protocol == "TCP" else 17 if protocol == "UDP" else 1
        features = np.array([[proto_num, length, frequency]])

        try:
            features_scaled = self.scaler.transform(features)
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            confidence = probabilities[prediction] * 100
            return int(prediction), float(confidence)
        except:
            return 0, 0.0
