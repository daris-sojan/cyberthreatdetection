import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import pandas as pd
from datetime import datetime, timedelta
import joblib
import os

class MLDetector:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.dbscan = DBSCAN(eps=0.3, min_samples=2)
        self.scaler = StandardScaler()
        self.model_path = "models/anomaly_detector.joblib"
        self._load_or_create_model()
        
    def _load_or_create_model(self):
        if os.path.exists(self.model_path):
            self.isolation_forest = joblib.load(self.model_path)
        else:
            os.makedirs("models", exist_ok=True)
            joblib.dump(self.isolation_forest, self.model_path)
    
    def _extract_features(self, log_entries):
        features = []
        for entry in log_entries:
            # Extract time-based features
            hour = entry['timestamp'].hour
            minute = entry['timestamp'].minute
            weekday = entry['timestamp'].weekday()
            
            # Extract IP-based features
            ip = entry.get('details', {}).get('ip', '0.0.0.0')  # Default IP if not found
            ip_parts = ip.split('.')
            ip_numeric = [int(part) for part in ip_parts]
            
            # Combine features
            feature_vector = [hour, minute, weekday] + ip_numeric
            features.append(feature_vector)
        
        return np.array(features)
    
    def detect_anomalies(self, log_entries):
        if len(log_entries) < 2:
            return []
        
        # Extract features
        features = self._extract_features(log_entries)
        
        # Scale features
        scaled_features = self.scaler.fit_transform(features)
        
        # Detect anomalies using Isolation Forest
        anomaly_scores = self.isolation_forest.fit_predict(scaled_features)
        
        # Cluster similar anomalies using DBSCAN
        clusters = self.dbscan.fit_predict(scaled_features)
        
        # Identify anomalous entries
        anomalies = []
        for i, (score, cluster) in enumerate(zip(anomaly_scores, clusters)):
            if score == -1:  # Anomaly detected
                anomalies.append({
                    'entry': log_entries[i],
                    'anomaly_score': abs(self.isolation_forest.score_samples([scaled_features[i]])[0]),
                    'cluster': int(cluster)
                })
        
        return anomalies
    
    def update_model(self, new_log_entries):
        """Update the model with new data"""
        features = self._extract_features(new_log_entries)
        scaled_features = self.scaler.fit_transform(features)
        self.isolation_forest.fit(scaled_features)
        joblib.dump(self.isolation_forest, self.model_path)
    
    def get_anomaly_patterns(self, anomalies):
        """Analyze patterns in detected anomalies"""
        patterns = []
        
        # Group anomalies by cluster
        clusters = {}
        for anomaly in anomalies:
            cluster = anomaly['cluster']
            if cluster not in clusters:
                clusters[cluster] = []
            clusters[cluster].append(anomaly)
        
        # Analyze each cluster
        for cluster_id, cluster_anomalies in clusters.items():
            if cluster_id == -1:  # Skip noise points
                continue
                
            # Extract common patterns
            ips = [a['entry'].get('details', {}).get('ip', '0.0.0.0') for a in cluster_anomalies]
            times = [a['entry']['timestamp'] for a in cluster_anomalies]
            
            pattern = {
                'cluster_id': cluster_id,
                'size': len(cluster_anomalies),
                'common_ips': list(set(ips)),
                'time_range': {
                    'start': min(times),
                    'end': max(times)
                },
                'avg_anomaly_score': np.mean([a['anomaly_score'] for a in cluster_anomalies])
            }
            patterns.append(pattern)
        
        return patterns 