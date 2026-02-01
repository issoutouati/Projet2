"""
Machine Learning components for ACARS threat detection and classification.
"""

import numpy as np
import pandas as pd
import logging
import pickle
import os
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import Dense, LSTM, Dropout, Input
from tensorflow.keras.optimizers import Adam
import asyncio
import json

from core.system import ThreatEvent, AttackType, ThreatLevel


class ThreatClassifier:
    """ML-based threat classification using supervised learning."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("acars.ml.classifier")
        self.model = None
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.scaler = StandardScaler()
        self.feature_names = []
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
        
        # Model paths
        self.model_dir = config.get('model_dir', '/home/engine/project/ml/models')
        self.model_path = os.path.join(self.model_dir, 'threat_classifier.pkl')
        self.vectorizer_path = os.path.join(self.model_dir, 'vectorizer.pkl')
        self.scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        
        # Training data
        self.training_data = []
        self.training_labels = []
        
    def initialize(self):
        """Initialize the classifier."""
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Try to load existing model
        if self.load_model():
            self.logger.info("Loaded existing threat classification model")
        else:
            self.logger.info("No existing model found, will need training data")
            
    def add_training_data(self, features: List[Dict[str, Any]], labels: List[AttackType]):
        """Add training data for the classifier."""
        self.training_data.extend(features)
        self.training_labels.extend(labels)
        
        if len(self.training_data) >= 100:  # Minimum training data
            self.train_model()
            
    def train_model(self):
        """Train the threat classification model."""
        if len(self.training_data) < 100:
            self.logger.warning("Insufficient training data for model training")
            return False
            
        try:
            self.logger.info(f"Training threat classifier with {len(self.training_data)} samples")
            
            # Extract features and labels
            X = self._extract_features(self.training_data)
            y = [label.value for label in self.training_labels]
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train Random Forest classifier
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'
            )
            
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            
            self.logger.info(f"Model training completed. Accuracy: {accuracy:.3f}")
            
            # Save model
            self.save_model()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            return False
            
    def classify_threat(self, threat_data: Dict[str, Any]) -> Tuple[AttackType, float]:
        """Classify a threat using the trained model."""
        if self.model is None:
            return AttackType.UNKNOWN, 0.0
            
        try:
            # Extract features
            features = self._extract_features([threat_data])
            features_scaled = self.scaler.transform(features)
            
            # Predict
            probabilities = self.model.predict_proba(features_scaled)[0]
            predicted_class = self.model.predict(features_scaled)[0]
            confidence = np.max(probabilities)
            
            # Convert back to AttackType
            attack_type = AttackType(predicted_class)
            
            return attack_type, confidence
            
        except Exception as e:
            self.logger.error(f"Error classifying threat: {e}")
            return AttackType.UNKNOWN, 0.0
            
    def _extract_features(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """Extract features from threat data."""
        features = []
        
        for item in data:
            feature_vector = []
            
            # Numerical features
            feature_vector.extend([
                item.get('confidence', 0.0),
                item.get('response_time', 0.0),
                item.get('bytes_transferred', 0),
                item.get('requests_count', 0),
                len(item.get('headers', {})),
                len(item.get('payload', '')),
                item.get('status_code', 0),
                1 if item.get('failed_login', False) else 0
            ])
            
            # Categorical features (encoded)
            attack_types = ['sql_injection', 'xss', 'ddos', 'brute_force', 'malware', 'port_scan']
            for at in attack_types:
                feature_vector.append(1 if item.get('attack_type') == at else 0)
                
            # Text features (using TF-IDF on description)
            if self.vectorizer.vocabulary_:
                text_vector = self.vectorizer.transform([item.get('description', '')]).toarray()[0]
                feature_vector.extend(text_vector)
            else:
                # If no vocabulary, use simple text features
                description = item.get('description', '').lower()
                feature_vector.extend([
                    len(description),
                    description.count('sql'),
                    description.count('script'),
                    description.count('injection'),
                    description.count('attack')
                ])
                
            features.append(feature_vector)
            
        return np.array(features)
        
    def save_model(self):
        """Save trained model to disk."""
        try:
            if self.model:
                with open(self.model_path, 'wb') as f:
                    pickle.dump(self.model, f)
                    
            with open(self.vectorizer_path, 'wb') as f:
                pickle.dump(self.vectorizer, f)
                
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
                
            self.logger.info("Model saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
            
    def load_model(self) -> bool:
        """Load trained model from disk."""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                    
            if os.path.exists(self.vectorizer_path):
                with open(self.vectorizer_path, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                    
            if os.path.exists(self.scaler_path):
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                    
            return self.model is not None
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return False


class AnomalyDetector:
    """Unsupervised anomaly detection for network traffic."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("acars.ml.anomaly")
        self.model = IsolationForest(
            contamination=config.get('contamination', 0.1),
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Model paths
        self.model_dir = config.get('model_dir', '/home/engine/project/ml/models')
        self.model_path = os.path.join(self.model_dir, 'anomaly_detector.pkl')
        self.scaler_path = os.path.join(self.model_dir, 'anomaly_scaler.pkl')
        
        # Data storage
        self.baseline_data = []
        self.normal_threshold = config.get('normal_threshold', -0.5)
        
    def initialize(self):
        """Initialize the anomaly detector."""
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Try to load existing model
        if self.load_model():
            self.logger.info("Loaded existing anomaly detection model")
            self.is_trained = True
        else:
            self.logger.info("No existing anomaly model found, will need baseline data")
            
    def add_baseline_data(self, data: List[Dict[str, Any]]):
        """Add baseline data for normal behavior."""
        self.baseline_data.extend(data)
        
        if len(self.baseline_data) >= 1000:  # Minimum baseline data
            self.train_model()
            
    def train_model(self):
        """Train the anomaly detection model."""
        if len(self.baseline_data) < 1000:
            self.logger.warning("Insufficient baseline data for anomaly detection training")
            return False
            
        try:
            self.logger.info(f"Training anomaly detector with {len(self.baseline_data)} baseline samples")
            
            # Extract features from baseline data
            features = self._extract_features(self.baseline_data)
            
            # Scale features
            features_scaled = self.scaler.fit_transform(features)
            
            # Train isolation forest
            self.model.fit(features_scaled)
            
            # Evaluate on training data to set threshold
            anomaly_scores = self.model.decision_function(features_scaled)
            threshold = np.percentile(anomaly_scores, 10)  # Bottom 10% as anomalies
            self.normal_threshold = threshold
            
            self.logger.info(f"Anomaly threshold set to: {threshold:.3f}")
            
            # Save model
            self.save_model()
            self.is_trained = True
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error training anomaly detector: {e}")
            return False
            
    def detect_anomaly(self, data: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect if data point is anomalous."""
        if not self.is_trained:
            return False, 0.0
            
        try:
            # Extract features
            features = self._extract_features([data])
            features_scaled = self.scaler.transform(features)
            
            # Get anomaly score
            anomaly_score = self.model.decision_function(features_scaled)[0]
            is_anomaly = self.model.predict(features_scaled)[0] == -1
            
            return is_anomaly, anomaly_score
            
        except Exception as e:
            self.logger.error(f"Error detecting anomaly: {e}")
            return False, 0.0
            
    def _extract_features(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """Extract features from network traffic data."""
        features = []
        
        for item in data:
            feature_vector = [
                item.get('request_rate', 0),
                item.get('connection_count', 0),
                item.get('bytes_per_second', 0),
                item.get('error_rate', 0),
                item.get('response_time', 0),
                item.get('unique_ips', 0),
                item.get('failed_logins', 0),
                item.get('unique_endpoints', 0)
            ]
            
            features.append(feature_vector)
            
        return np.array(features)
        
    def save_model(self):
        """Save trained model to disk."""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
                
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
                
            self.logger.info("Anomaly model saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving anomaly model: {e}")
            
    def load_model(self) -> bool:
        """Load trained model from disk."""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                    
            if os.path.exists(self.scaler_path):
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                    
            return os.path.exists(self.model_path)
            
        except Exception as e:
            self.logger.error(f"Error loading anomaly model: {e}")
            return False


class LSTMThreatPredictor:
    """LSTM-based sequential threat prediction."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("acars.ml.predictor")
        self.model = None
        self.sequence_length = config.get('sequence_length', 50)
        self.feature_dim = config.get('feature_dim', 10)
        
        # Model paths
        self.model_dir = config.get('model_dir', '/home/engine/project/ml/models')
        self.model_path = os.path.join(self.model_dir, 'lstm_predictor.h5')
        
        # Training data storage
        self.sequences = []
        self.labels = []
        
    def initialize(self):
        """Initialize the LSTM predictor."""
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Try to load existing model
        if self.load_model():
            self.logger.info("Loaded existing LSTM predictor model")
        else:
            self.logger.info("Building new LSTM predictor model")
            self._build_model()
            
    def _build_model(self):
        """Build the LSTM neural network."""
        self.model = Sequential([
            LSTM(50, return_sequences=True, input_shape=(self.sequence_length, self.feature_dim)),
            Dropout(0.2),
            LSTM(50, return_sequences=False),
            Dropout(0.2),
            Dense(25),
            Dense(len(AttackType), activation='softmax')
        ])
        
        self.model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
    def add_training_sequence(self, sequence: List[Dict[str, Any]], label: AttackType):
        """Add training sequence for the predictor."""
        if len(sequence) >= self.sequence_length:
            # Extract features from sequence
            features = self._extract_sequence_features(sequence)
            
            # Pad or truncate to sequence length
            if len(features) > self.sequence_length:
                features = features[:self.sequence_length]
            elif len(features) < self.sequence_length:
                # Pad with zeros
                padding = np.zeros((self.sequence_length - len(features), self.feature_dim))
                features = np.vstack([features, padding])
                
            self.sequences.append(features)
            self.labels.append(label.value)
            
        if len(self.sequences) >= 1000:  # Minimum training data
            self.train_model()
            
    def train_model(self):
        """Train the LSTM model."""
        if len(self.sequences) < 1000:
            self.logger.warning("Insufficient training sequences for LSTM training")
            return False
            
        try:
            self.logger.info(f"Training LSTM predictor with {len(self.sequences)} sequences")
            
            # Convert to numpy arrays
            X = np.array(self.sequences)
            y = np.array(self.labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Train model
            self.model.fit(
                X_train, y_train,
                validation_data=(X_test, y_test),
                epochs=10,
                batch_size=32,
                verbose=1
            )
            
            # Evaluate
            test_loss, test_accuracy = self.model.evaluate(X_test, y_test, verbose=0)
            self.logger.info(f"LSTM training completed. Test accuracy: {test_accuracy:.3f}")
            
            # Save model
            self.save_model()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error training LSTM model: {e}")
            return False
            
    def predict_next_threat(self, recent_data: List[Dict[str, Any]]) -> Tuple[AttackType, float]:
        """Predict next threat based on recent data sequence."""
        if self.model is None:
            return AttackType.UNKNOWN, 0.0
            
        try:
            # Extract features from recent data
            features = self._extract_sequence_features(recent_data)
            
            # Pad or truncate to sequence length
            if len(features) > self.sequence_length:
                features = features[-self.sequence_length:]
            elif len(features) < self.sequence_length:
                # Pad with zeros
                padding = np.zeros((self.sequence_length - len(features), self.feature_dim))
                features = np.vstack([padding, features])
                
            # Reshape for prediction
            features = features.reshape(1, self.sequence_length, self.feature_dim)
            
            # Predict
            predictions = self.model.predict(features, verbose=0)
            predicted_class = np.argmax(predictions[0])
            confidence = np.max(predictions[0])
            
            # Convert back to AttackType
            attack_type = AttackType(list(AttackType)[predicted_class].value)
            
            return attack_type, confidence
            
        except Exception as e:
            self.logger.error(f"Error predicting next threat: {e}")
            return AttackType.UNKNOWN, 0.0
            
    def _extract_sequence_features(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """Extract sequential features from threat data."""
        features = []
        
        for item in data:
            # Basic features
            feature_vector = [
                item.get('hour_of_day', 0) / 24.0,
                item.get('day_of_week', 0) / 7.0,
                item.get('confidence', 0.0),
                item.get('requests_per_minute', 0) / 1000.0,
                item.get('error_rate', 0.0),
                item.get('response_time', 0.0) / 10.0,
                1.0 if item.get('is_weekend', False) else 0.0,
                1.0 if item.get('is_business_hours', False) else 0.0,
                len(item.get('source_ips', [])) / 100.0,
                item.get('unique_users', 0) / 1000.0
            ]
            
            features.append(feature_vector)
            
        return np.array(features)
        
    def save_model(self):
        """Save trained model to disk."""
        try:
            if self.model:
                self.model.save(self.model_path)
                self.logger.info("LSTM model saved successfully")
                
        except Exception as e:
            self.logger.error(f"Error saving LSTM model: {e}")
            
    def load_model(self) -> bool:
        """Load trained model from disk."""
        try:
            if os.path.exists(self.model_path):
                self.model = tf.keras.models.load_model(self.model_path)
                self._build_model()  # Ensure model structure is set
                self.model = tf.keras.models.load_model(self.model_path)
                return True
                
        except Exception as e:
            self.logger.error(f"Error loading LSTM model: {e}")
            
        return False


class MLThreatDetectionEngine:
    """Main ML engine that coordinates all ML components."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("acars.ml.engine")
        
        # Initialize ML components
        self.classifier = ThreatClassifier(config.get('threat_classification', {}))
        self.anomaly_detector = AnomalyDetector(config.get('anomaly_detection', {}))
        self.predictor = LSTMThreatPredictor(config.get('threat_prediction', {}))
        
        # Data storage
        self.threat_history = []
        self.network_baseline = []
        
        # Initialize components
        self.classifier.initialize()
        self.anomaly_detector.initialize()
        self.predictor.initialize()
        
    async def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat using all ML components."""
        results = {
            'original_data': threat_data,
            'analysis_timestamp': datetime.now().isoformat(),
            'classification': None,
            'anomaly_score': 0.0,
            'is_anomaly': False,
            'prediction': None,
            'confidence': 0.0,
            'recommendations': []
        }
        
        try:
            # 1. Threat classification
            predicted_type, classification_confidence = self.classifier.classify_threat(threat_data)
            results['classification'] = {
                'predicted_type': predicted_type.value,
                'confidence': classification_confidence
            }
            
            # 2. Anomaly detection
            is_anomaly, anomaly_score = self.anomaly_detector.detect_anomaly(threat_data)
            results['anomaly_score'] = anomaly_score
            results['is_anomaly'] = is_anomaly
            
            # 3. Threat prediction (based on recent history)
            recent_data = self.threat_history[-50:] if len(self.threat_history) >= 50 else self.threat_history
            if recent_data:
                predicted_threat, prediction_confidence = self.predictor.predict_next_threat(recent_data)
                results['prediction'] = {
                    'predicted_threat': predicted_threat.value,
                    'confidence': prediction_confidence
                }
                
            # 4. Generate recommendations
            results['recommendations'] = self._generate_recommendations(results)
            
            # Update training data
            self.threat_history.append(threat_data)
            if len(self.threat_history) > 10000:  # Keep last 10k threats
                self.threat_history = self.threat_history[-5000:]
                
        except Exception as e:
            self.logger.error(f"Error in ML analysis: {e}")
            
        return results
        
    def add_training_data(self, threat_data: Dict[str, Any], actual_type: AttackType):
        """Add training data for all ML components."""
        try:
            # Add to threat classifier
            self.classifier.add_training_data([threat_data], [actual_type])
            
            # Add to anomaly detector if it's normal behavior
            if threat_data.get('is_baseline', False):
                self.anomaly_detector.add_baseline_data([threat_data])
                
            # Add to LSTM predictor
            self.predictor.add_training_sequence(self.threat_history[-50:], actual_type)
            
        except Exception as e:
            self.logger.error(f"Error adding training data: {e}")
            
    def _generate_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on ML analysis."""
        recommendations = []
        
        # Classification-based recommendations
        predicted_type = analysis_results.get('classification', {}).get('predicted_type')
        if predicted_type == 'sql_injection':
            recommendations.append("Enable database query filtering and input validation")
            recommendations.append("Review and sanitize all database queries")
            
        elif predicted_type == 'ddos':
            recommendations.append("Activate rate limiting and traffic filtering")
            recommendations.append("Consider using CDN with DDoS protection")
            
        elif predicted_type == 'brute_force':
            recommendations.append("Implement account lockout policies")
            recommendations.append("Enable multi-factor authentication")
            
        # Anomaly-based recommendations
        if analysis_results.get('is_anomaly', False):
            recommendations.append("Investigate unusual network behavior patterns")
            recommendations.append("Review access logs for anomalies")
            
        # Prediction-based recommendations
        prediction = analysis_results.get('prediction', {})
        if prediction.get('confidence', 0) > 0.8:
            recommendations.append(f"Prepare for potential {prediction['predicted_threat']} attack")
            
        return recommendations
        
    def get_model_performance(self) -> Dict[str, Any]:
        """Get performance metrics for all ML models."""
        return {
            'classifier': {
                'model_loaded': self.classifier.model is not None,
                'training_samples': len(self.classifier.training_data)
            },
            'anomaly_detector': {
                'model_trained': self.anomaly_detector.is_trained,
                'baseline_samples': len(self.anomaly_detector.baseline_data)
            },
            'predictor': {
                'model_loaded': self.predictor.model is not None,
                'training_sequences': len(self.predictor.sequences)
            },
            'threat_history_size': len(self.threat_history)
        }