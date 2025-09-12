"""Classical machine learning models for phishing detection."""

import pickle
import joblib
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
import pandas as pd

from app.config.logging import get_logger
from app.config.settings import settings

logger = get_logger(__name__)


class ClassicalModel:
    """Base class for classical machine learning models."""
    
    def __init__(self, model_type: str = "random_forest"):
        """Initialize classical model."""
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = None
        
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the specific model type."""
        if self.model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
        elif self.model_type == "svm":
            self.model = SVC(
                kernel='rbf',
                C=1.0,
                probability=True,
                random_state=42
            )
        elif self.model_type == "logistic_regression":
            self.model = LogisticRegression(
                random_state=42,
                max_iter=1000
            )
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def train(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """Train the model."""
        logger.info(f"Training {self.model_type} model with {len(X)} samples")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_pred_proba)
        }
        
        # Cross-validation
        cv_scores = cross_val_score(
            self.model, X_train_scaled, y_train, cv=5, scoring='accuracy'
        )
        metrics['cv_accuracy_mean'] = cv_scores.mean()
        metrics['cv_accuracy_std'] = cv_scores.std()
        
        self.is_trained = True
        
        logger.info(f"Model training completed. Accuracy: {metrics['accuracy']:.4f}")
        return metrics
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions."""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)[:, 1]
        
        return predictions, probabilities
    
    def predict_single(self, features: List[float]) -> Tuple[int, float]:
        """Predict single sample."""
        X = np.array([features])
        predictions, probabilities = self.predict(X)
        return int(predictions[0]), float(probabilities[0])
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance (for tree-based models)."""
        if not self.is_trained:
            return {}
        
        if hasattr(self.model, 'feature_importances_'):
            importance = self.model.feature_importances_
            feature_names = self.feature_names or [f"feature_{i}" for i in range(len(importance))]
            return dict(zip(feature_names, importance))
        
        return {}
    
    def save_model(self, filepath: str):
        """Save model to file."""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'model_type': self.model_type,
            'is_trained': self.is_trained,
            'feature_names': self.feature_names
        }
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load model from file."""
        model_data = joblib.load(filepath)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.model_type = model_data['model_type']
        self.is_trained = model_data['is_trained']
        self.feature_names = model_data.get('feature_names')
        logger.info(f"Model loaded from {filepath}")


class ModelEnsemble:
    """Ensemble of classical models for improved performance."""
    
    def __init__(self, models: List[str] = None):
        """Initialize model ensemble."""
        self.models = models or ["random_forest", "svm", "logistic_regression"]
        self.classifiers = {}
        self.weights = None
        self.is_trained = False
        
        for model_type in self.models:
            self.classifiers[model_type] = ClassicalModel(model_type)
    
    def train(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Dict[str, float]]:
        """Train all models in the ensemble."""
        logger.info(f"Training ensemble with {len(self.models)} models")
        
        results = {}
        
        for model_type, classifier in self.classifiers.items():
            logger.info(f"Training {model_type}")
            metrics = classifier.train(X, y)
            results[model_type] = metrics
        
        # Calculate ensemble weights based on performance
        self.weights = {}
        for model_type, metrics in results.items():
            # Weight based on F1 score
            self.weights[model_type] = metrics['f1_score']
        
        # Normalize weights
        total_weight = sum(self.weights.values())
        if total_weight > 0:
            self.weights = {k: v / total_weight for k, v in self.weights.items()}
        
        self.is_trained = True
        
        logger.info(f"Ensemble training completed. Weights: {self.weights}")
        return results
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make ensemble predictions."""
        if not self.is_trained:
            raise ValueError("Ensemble must be trained before making predictions")
        
        predictions = []
        probabilities = []
        
        for model_type, classifier in self.classifiers.items():
            pred, prob = classifier.predict(X)
            predictions.append(pred)
            probabilities.append(prob)
        
        # Weighted voting
        weighted_probs = np.zeros_like(probabilities[0])
        for i, model_type in enumerate(self.models):
            weighted_probs += self.weights[model_type] * probabilities[i]
        
        # Final prediction
        final_predictions = (weighted_probs > 0.5).astype(int)
        
        return final_predictions, weighted_probs
    
    def predict_single(self, features: List[float]) -> Tuple[int, float]:
        """Predict single sample with ensemble."""
        X = np.array([features])
        predictions, probabilities = self.predict(X)
        return int(predictions[0]), float(probabilities[0])
    
    def save_ensemble(self, filepath: str):
        """Save ensemble to file."""
        ensemble_data = {
            'models': self.models,
            'weights': self.weights,
            'is_trained': self.is_trained,
            'classifiers': self.classifiers
        }
        joblib.dump(ensemble_data, filepath)
        logger.info(f"Ensemble saved to {filepath}")
    
    def load_ensemble(self, filepath: str):
        """Load ensemble from file."""
        ensemble_data = joblib.load(filepath)
        self.models = ensemble_data['models']
        self.weights = ensemble_data['weights']
        self.is_trained = ensemble_data['is_trained']
        self.classifiers = ensemble_data['classifiers']
        logger.info(f"Ensemble loaded from {filepath}")


class ModelManager:
    """Manager for classical models."""
    
    def __init__(self):
        """Initialize model manager."""
        self.ensemble = ModelEnsemble()
        self.current_model = None
    
    def train_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train all models."""
        results = self.ensemble.train(X, y)
        
        # Set current model to ensemble
        self.current_model = self.ensemble
        
        return results
    
    def predict(self, features: List[float]) -> Tuple[int, float]:
        """Make prediction with current model."""
        if self.current_model is None:
            raise ValueError("No model available for prediction")
        
        return self.current_model.predict_single(features)
    
    def get_model_performance(self) -> Dict[str, float]:
        """Get current model performance metrics."""
        if self.current_model is None:
            return {}
        
        if hasattr(self.current_model, 'weights'):
            return self.current_model.weights
        
        return {}
    
    def save_models(self, base_path: str):
        """Save all models."""
        if self.ensemble.is_trained:
            self.ensemble.save_ensemble(f"{base_path}/ensemble.pkl")
        
        for model_type, classifier in self.ensemble.classifiers.items():
            if classifier.is_trained:
                classifier.save_model(f"{base_path}/{model_type}.pkl")
    
    def load_models(self, base_path: str):
        """Load all models."""
        try:
            self.ensemble.load_ensemble(f"{base_path}/ensemble.pkl")
            self.current_model = self.ensemble
        except FileNotFoundError:
            logger.warning("Ensemble model not found, loading individual models")
            for model_type in self.ensemble.models:
                try:
                    self.ensemble.classifiers[model_type].load_model(f"{base_path}/{model_type}.pkl")
                except FileNotFoundError:
                    logger.warning(f"Model {model_type} not found")

