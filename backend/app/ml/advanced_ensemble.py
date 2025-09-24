"""Advanced ensemble machine learning system for PhishNet.

This module implements:
1. Content Transformer Model (BERT-based)
2. URL Feature-Based Model (engineered features)
3. Sender Behavior Model (behavioral patterns)
4. Adversarial training capabilities
5. Explainability (LIME/SHAP integration)
6. Active learning pipeline
"""

import asyncio
import json
import pickle
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import hashlib
import logging

# ML Libraries
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.calibration import CalibratedClassifierCV
import joblib

# Deep Learning
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from transformers import AutoTokenizer, AutoModel, AutoConfig
    PYTORCH_AVAILABLE = True
except ImportError:
    PYTORCH_AVAILABLE = False
    logging.warning("PyTorch not available. Transformer models will be disabled.")

# Explainability
try:
    import lime
    import lime.lime_tabular
    import shap
    EXPLAINABILITY_AVAILABLE = True
except ImportError:
    EXPLAINABILITY_AVAILABLE = False
    logging.warning("LIME/SHAP not available. Explainability features will be limited.")

# MLflow for model versioning
try:
    import mlflow
    import mlflow.sklearn
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False
    logging.warning("MLflow not available. Model versioning will be limited.")

from app.config.logging import get_logger
from app.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class ModelMetrics:
    """Model performance metrics."""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    false_positive_rate: float
    false_negative_rate: float
    timestamp: datetime
    model_version: str
    dataset_size: int


@dataclass
class PredictionExplanation:
    """Model prediction explanation."""
    prediction: float
    confidence: float
    top_features: List[Tuple[str, float]]  # (feature_name, importance)
    explanation_text: str
    model_used: str
    explanation_method: str = "lime"


@dataclass
class EnsembleResult:
    """Ensemble prediction result with explanations."""
    is_phishing: bool
    confidence: float
    risk_score: float
    individual_predictions: Dict[str, float]
    explanation: PredictionExplanation
    processing_time_ms: float


class ContentTransformerModel:
    """BERT-based transformer model for email content analysis."""
    
    def __init__(self, model_name: str = "distilbert-base-uncased"):
        """Initialize transformer model."""
        self.model_name = model_name
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = None
        self.model = None
        self.classifier = None
        self.is_initialized = False
        
        if PYTORCH_AVAILABLE:
            self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the transformer model and tokenizer."""
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModel.from_pretrained(self.model_name)
            self.model.to(self.device)
            
            # Add classification head
            self.classifier = nn.Sequential(
                nn.Linear(self.model.config.hidden_size, 256),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(256, 64),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(64, 1),
                nn.Sigmoid()
            ).to(self.device)
            
            self.is_initialized = True
            logger.info(f"Initialized transformer model: {self.model_name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize transformer model: {e}")
            self.is_initialized = False
    
    def encode_text(self, text: str, max_length: int = 512) -> torch.Tensor:
        """Encode text using transformer model."""
        if not self.is_initialized:
            return torch.zeros(768)  # Fallback embedding size
        
        try:
            inputs = self.tokenizer(
                text,
                max_length=max_length,
                padding=True,
                truncation=True,
                return_tensors="pt"
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                # Use [CLS] token embedding
                embeddings = outputs.last_hidden_state[:, 0, :]
            
            return embeddings.cpu()
            
        except Exception as e:
            logger.error(f"Error encoding text: {e}")
            return torch.zeros(768)
    
    def predict(self, text: str) -> Tuple[float, float]:
        """Predict phishing probability for text."""
        if not self.is_initialized:
            return 0.5, 0.5  # Fallback
        
        try:
            embeddings = self.encode_text(text)
            embeddings = embeddings.to(self.device)
            
            with torch.no_grad():
                prediction = self.classifier(embeddings)
                confidence = prediction.item()
            
            return confidence, confidence
            
        except Exception as e:
            logger.error(f"Error in transformer prediction: {e}")
            return 0.5, 0.5


class URLFeatureModel:
    """Feature-engineered model for URL analysis."""
    
    def __init__(self):
        """Initialize URL feature model."""
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            'url_length', 'domain_length', 'subdomain_count', 'path_length',
            'query_length', 'fragment_length', 'special_char_count',
            'digit_ratio', 'vowel_consonant_ratio', 'entropy',
            'has_ip_address', 'has_port', 'is_shortened', 'has_suspicious_tld',
            'domain_age_days', 'ssl_cert_valid', 'redirect_count',
            'similarity_to_popular_sites', 'typosquatting_score', 'homograph_score'
        ]
    
    def extract_url_features(self, url: str) -> np.ndarray:
        """Extract comprehensive URL features."""
        from urllib.parse import urlparse
        import re
        import math
        
        try:
            parsed = urlparse(url)
            features = []
            
            # Basic length features
            features.append(len(url))
            features.append(len(parsed.netloc))
            features.append(len(parsed.netloc.split('.')) - 1)
            features.append(len(parsed.path))
            features.append(len(parsed.query))
            features.append(len(parsed.fragment))
            
            # Character analysis
            special_chars = len(re.findall(r'[^a-zA-Z0-9]', url))
            features.append(special_chars)
            
            digits = len(re.findall(r'\d', url))
            features.append(digits / len(url) if url else 0)
            
            vowels = len(re.findall(r'[aeiouAEIOU]', url))
            consonants = len(re.findall(r'[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]', url))
            features.append(vowels / (consonants + 1))
            
            # Entropy calculation
            if url:
                prob = [url.count(c) / len(url) for c in set(url)]
                entropy = -sum(p * math.log2(p) for p in prob if p > 0)
                features.append(entropy)
            else:
                features.append(0)
            
            # Suspicious indicators
            features.append(1 if re.match(r'^\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0)
            features.append(1 if ':' in parsed.netloc and parsed.port else 0)
            
            # URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd']
            features.append(1 if any(s in parsed.netloc for s in shorteners) else 0)
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            features.append(1 if any(tld in url.lower() for tld in suspicious_tlds) else 0)
            
            # Placeholder for external checks (would be implemented with actual APIs)
            features.append(365)  # Domain age placeholder
            features.append(1)    # SSL cert valid placeholder
            features.append(0)    # Redirect count placeholder
            features.append(0.1)  # Similarity score placeholder
            features.append(0.05) # Typosquatting score placeholder
            features.append(0.02) # Homograph score placeholder
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Error extracting URL features: {e}")
            return np.zeros((1, len(self.feature_names)))
    
    def predict(self, url: str) -> Tuple[float, float]:
        """Predict phishing probability for URL."""
        if not self.is_trained:
            return 0.5, 0.5
        
        try:
            features = self.extract_url_features(url)
            features_scaled = self.scaler.transform(features)
            
            prediction = self.model.predict_proba(features_scaled)[0]
            confidence = max(prediction)
            phishing_prob = prediction[1] if len(prediction) > 1 else prediction[0]
            
            return phishing_prob, confidence
            
        except Exception as e:
            logger.error(f"Error in URL prediction: {e}")
            return 0.5, 0.5


class SenderBehaviorModel:
    """Model for analyzing sender behavioral patterns."""
    
    def __init__(self):
        """Initialize sender behavior model."""
        self.model = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=8,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.sender_history = {}  # Cache for sender patterns
        
    def extract_sender_features(self, sender_email: str, sender_history: Dict) -> np.ndarray:
        """Extract sender behavioral features."""
        try:
            features = []
            
            # Basic sender features
            domain = sender_email.split('@')[1] if '@' in sender_email else ""
            features.append(len(sender_email))
            features.append(len(domain))
            features.append(1 if any(char.isdigit() for char in sender_email) else 0)
            
            # Historical patterns (from sender_history dict)
            features.append(sender_history.get('email_count', 0))
            features.append(sender_history.get('avg_time_between_emails', 24))
            features.append(sender_history.get('unique_subjects_ratio', 1.0))
            features.append(sender_history.get('spam_reports', 0))
            features.append(sender_history.get('reputation_score', 0.5))
            
            # Domain reputation features
            features.append(sender_history.get('domain_age_days', 365))
            features.append(sender_history.get('mx_record_valid', 1))
            features.append(sender_history.get('spf_valid', 1))
            features.append(sender_history.get('dkim_valid', 1))
            features.append(sender_history.get('dmarc_valid', 1))
            
            # Behavioral anomalies
            features.append(sender_history.get('sends_at_odd_hours', 0))
            features.append(sender_history.get('bulk_sending_pattern', 0))
            features.append(sender_history.get('reply_rate', 0.1))
            features.append(sender_history.get('bounce_rate', 0.05))
            
            # Geographic/network features
            features.append(sender_history.get('ip_changes_frequently', 0))
            features.append(sender_history.get('suspicious_geo_pattern', 0))
            features.append(sender_history.get('uses_vpn_proxy', 0))
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Error extracting sender features: {e}")
            return np.zeros((1, 20))  # 20 features
    
    def predict(self, sender_email: str, sender_history: Optional[Dict] = None) -> Tuple[float, float]:
        """Predict phishing probability based on sender behavior."""
        if not self.is_trained:
            return 0.5, 0.5
        
        if sender_history is None:
            sender_history = self.sender_history.get(sender_email, {})
        
        try:
            features = self.extract_sender_features(sender_email, sender_history)
            features_scaled = self.scaler.transform(features)
            
            prediction = self.model.predict_proba(features_scaled)[0]
            confidence = max(prediction)
            phishing_prob = prediction[1] if len(prediction) > 1 else prediction[0]
            
            return phishing_prob, confidence
            
        except Exception as e:
            logger.error(f"Error in sender prediction: {e}")
            return 0.5, 0.5


class AdversarialTrainer:
    """Adversarial training system for robust models."""
    
    def __init__(self):
        """Initialize adversarial trainer."""
        self.mutation_strategies = [
            self._character_substitution,
            self._typosquatting,
            self._url_obfuscation,
            self._content_paraphrasing,
            self._encoding_attacks
        ]
    
    def _character_substitution(self, text: str) -> str:
        """Apply character substitution attacks."""
        substitutions = {
            'o': '0', 'i': '1', 'l': '1', 'e': '3', 
            'a': '@', 's': '$', 'g': '9', 't': '7'
        }
        
        result = text.lower()
        for char, sub in substitutions.items():
            if np.random.random() < 0.1:  # 10% chance per character
                result = result.replace(char, sub)
        
        return result
    
    def _typosquatting(self, domain: str) -> str:
        """Generate typosquatted domain variations."""
        if '.' not in domain:
            return domain
        
        base_domain = domain.split('.')[0]
        tld = domain.split('.', 1)[1]
        
        mutations = [
            base_domain + 'ing.' + tld,
            base_domain + '-security.' + tld,
            base_domain.replace('o', '0') + '.' + tld,
            'secure-' + base_domain + '.' + tld,
            base_domain + '-verification.' + tld
        ]
        
        return np.random.choice(mutations)
    
    def _url_obfuscation(self, url: str) -> str:
        """Apply URL obfuscation techniques."""
        obfuscation_methods = [
            lambda u: u.replace('http://', 'hxxp://'),
            lambda u: u.replace('.', '[.]'),
            lambda u: u + '?' + ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), 10)),
            lambda u: u.replace('/', '%2F') if '/' in u else u
        ]
        
        method = np.random.choice(obfuscation_methods)
        return method(url)
    
    def _content_paraphrasing(self, content: str) -> str:
        """Apply content paraphrasing for adversarial samples."""
        # Simple paraphrasing rules
        paraphrases = {
            'urgent': ['immediate', 'pressing', 'critical'],
            'verify': ['confirm', 'validate', 'authenticate'],
            'account': ['profile', 'user account', 'credentials'],
            'suspended': ['frozen', 'blocked', 'deactivated'],
            'click here': ['tap here', 'click this link', 'follow this link']
        }
        
        result = content.lower()
        for original, alternatives in paraphrases.items():
            if original in result and np.random.random() < 0.3:
                replacement = np.random.choice(alternatives)
                result = result.replace(original, replacement)
        
        return result
    
    def _encoding_attacks(self, text: str) -> str:
        """Apply encoding-based attacks."""
        # Base64 partial encoding
        import base64
        
        if len(text) > 10:
            # Encode a random substring
            start = np.random.randint(0, len(text) - 5)
            end = start + 5
            substring = text[start:end]
            encoded = base64.b64encode(substring.encode()).decode()
            return text[:start] + encoded + text[end:]
        
        return text
    
    def generate_adversarial_samples(self, samples: List[Dict], num_mutations: int = 3) -> List[Dict]:
        """Generate adversarial samples from original data."""
        adversarial_samples = []
        
        for sample in samples:
            for _ in range(num_mutations):
                mutated_sample = sample.copy()
                
                # Apply random mutations
                mutation_strategy = np.random.choice(self.mutation_strategies)
                
                if 'content' in mutated_sample:
                    mutated_sample['content'] = mutation_strategy(mutated_sample['content'])
                
                if 'url' in mutated_sample:
                    mutated_sample['url'] = self._url_obfuscation(mutated_sample['url'])
                
                if 'sender' in mutated_sample:
                    if '@' in mutated_sample['sender']:
                        domain = mutated_sample['sender'].split('@')[1]
                        user = mutated_sample['sender'].split('@')[0]
                        mutated_domain = self._typosquatting(domain)
                        mutated_sample['sender'] = user + '@' + mutated_domain
                
                # Keep the same label (important for adversarial training)
                adversarial_samples.append(mutated_sample)
        
        return adversarial_samples


class ExplainabilityEngine:
    """LIME/SHAP-based model explainability."""
    
    def __init__(self):
        """Initialize explainability engine."""
        self.lime_explainer = None
        self.shap_explainer = None
        self.feature_names = []
        
    def setup_lime_explainer(self, training_data: np.ndarray, feature_names: List[str]):
        """Set up LIME explainer."""
        if not EXPLAINABILITY_AVAILABLE:
            logger.warning("LIME not available")
            return
        
        try:
            self.lime_explainer = lime.lime_tabular.LimeTabularExplainer(
                training_data,
                feature_names=feature_names,
                class_names=['legitimate', 'phishing'],
                mode='classification'
            )
            self.feature_names = feature_names
            logger.info("LIME explainer initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize LIME explainer: {e}")
    
    def explain_prediction(self, model, instance: np.ndarray, method: str = "lime") -> PredictionExplanation:
        """Generate explanation for model prediction."""
        try:
            prediction = model.predict_proba([instance])[0]
            confidence = max(prediction)
            phishing_prob = prediction[1] if len(prediction) > 1 else prediction[0]
            
            if method == "lime" and self.lime_explainer is not None:
                explanation = self.lime_explainer.explain_instance(
                    instance,
                    model.predict_proba,
                    num_features=5
                )
                
                top_features = explanation.as_list()
                explanation_text = f"Top factors: {', '.join([f'{name} ({weight:.3f})' for name, weight in top_features])}"
                
            elif method == "shap" and EXPLAINABILITY_AVAILABLE:
                # SHAP explanation (simplified)
                feature_importance = np.abs(instance) / (np.sum(np.abs(instance)) + 1e-8)
                top_indices = np.argsort(feature_importance)[-5:][::-1]
                
                top_features = [
                    (self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}", 
                     feature_importance[i])
                    for i in top_indices
                ]
                
                explanation_text = f"Top contributing features: {', '.join([f'{name} ({weight:.3f})' for name, weight in top_features])}"
                
            else:
                # Fallback explanation based on feature values
                top_indices = np.argsort(np.abs(instance))[-5:][::-1]
                top_features = [
                    (self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}", 
                     abs(instance[i]))
                    for i in top_indices
                ]
                explanation_text = "Basic feature importance analysis"
            
            return PredictionExplanation(
                prediction=phishing_prob,
                confidence=confidence,
                top_features=top_features,
                explanation_text=explanation_text,
                model_used=str(type(model).__name__),
                explanation_method=method
            )
            
        except Exception as e:
            logger.error(f"Error generating explanation: {e}")
            return PredictionExplanation(
                prediction=0.5,
                confidence=0.5,
                top_features=[],
                explanation_text="Explanation generation failed",
                model_used="unknown",
                explanation_method=method
            )


class ActiveLearningManager:
    """Active learning system for continuous model improvement."""
    
    def __init__(self):
        """Initialize active learning manager."""
        self.correction_queue = []
        self.retraining_threshold = 100  # Retrain after 100 corrections
        self.last_retrain = datetime.now()
        self.retrain_interval = timedelta(days=7)  # Weekly retraining
        
    def add_correction(self, email_data: Dict, correct_label: int, model_prediction: float, user_id: str):
        """Add analyst correction to the learning queue."""
        correction = {
            'email_data': email_data,
            'correct_label': correct_label,
            'model_prediction': model_prediction,
            'user_id': user_id,
            'timestamp': datetime.now(),
            'correction_id': hashlib.md5(
                f"{email_data.get('content', '')}{correct_label}{datetime.now()}".encode()
            ).hexdigest()
        }
        
        self.correction_queue.append(correction)
        logger.info(f"Added correction to queue. Queue size: {len(self.correction_queue)}")
        
        # Check if retraining is needed
        if self.should_retrain():
            asyncio.create_task(self.trigger_retraining())
    
    def should_retrain(self) -> bool:
        """Determine if model retraining should be triggered."""
        queue_threshold_met = len(self.correction_queue) >= self.retraining_threshold
        time_threshold_met = datetime.now() - self.last_retrain > self.retrain_interval
        
        return queue_threshold_met or time_threshold_met
    
    async def trigger_retraining(self):
        """Trigger model retraining with corrected data."""
        try:
            logger.info("Starting model retraining with active learning data")
            
            # Prepare training data from corrections
            training_samples = []
            labels = []
            
            for correction in self.correction_queue:
                training_samples.append(correction['email_data'])
                labels.append(correction['correct_label'])
            
            # This would integrate with the ensemble training pipeline
            # For now, just log the retraining trigger
            logger.info(f"Retraining with {len(training_samples)} corrected samples")
            
            # Clear the queue after processing
            self.correction_queue.clear()
            self.last_retrain = datetime.now()
            
        except Exception as e:
            logger.error(f"Error during retraining: {e}")


class AdvancedEnsembleML:
    """Advanced ensemble ML system with adversarial hardening and explainability."""
    
    def __init__(self):
        """Initialize the advanced ensemble system."""
        self.content_model = ContentTransformerModel() if PYTORCH_AVAILABLE else None
        self.url_model = URLFeatureModel()
        self.sender_model = SenderBehaviorModel()
        
        self.adversarial_trainer = AdversarialTrainer()
        self.explainability_engine = ExplainabilityEngine()
        self.active_learning = ActiveLearningManager()
        
        # Ensemble weights (adaptive)
        self.ensemble_weights = {
            'content': 0.4,
            'url': 0.35,
            'sender': 0.25
        }
        
        # Model versioning
        self.model_version = "1.0.0"
        self.last_metrics = None
        self.model_registry = {}
        
        # Performance tracking
        self.prediction_cache = {}
        self.metrics_history = []
        
        logger.info("Advanced ensemble ML system initialized")
    
    async def train_ensemble(self, training_data: List[Dict], labels: List[int], 
                           use_adversarial: bool = True) -> ModelMetrics:
        """Train the complete ensemble with adversarial hardening."""
        start_time = datetime.now()
        
        try:
            # Generate adversarial samples if requested
            if use_adversarial:
                logger.info("Generating adversarial training samples...")
                adversarial_samples = self.adversarial_trainer.generate_adversarial_samples(
                    training_data, num_mutations=2
                )
                
                # Combine original and adversarial samples
                all_samples = training_data + adversarial_samples
                all_labels = labels + labels * 2  # Same labels for adversarial samples
            else:
                all_samples = training_data
                all_labels = labels
            
            # Train individual models
            logger.info(f"Training ensemble on {len(all_samples)} samples...")
            
            # Train URL model
            url_features = []
            for sample in all_samples:
                if 'urls' in sample and sample['urls']:
                    features = self.url_model.extract_url_features(sample['urls'][0])
                    url_features.append(features.flatten())
                else:
                    url_features.append(np.zeros(self.url_model.feature_names.__len__()))
            
            if url_features:
                X_url = np.array(url_features)
                self.url_model.scaler.fit(X_url)
                X_url_scaled = self.url_model.scaler.transform(X_url)
                self.url_model.model.fit(X_url_scaled, all_labels)
                self.url_model.is_trained = True
                logger.info("URL model trained successfully")
            
            # Train sender model
            sender_features = []
            for sample in all_samples:
                sender = sample.get('sender', 'unknown@example.com')
                sender_hist = sample.get('sender_history', {})
                features = self.sender_model.extract_sender_features(sender, sender_hist)
                sender_features.append(features.flatten())
            
            if sender_features:
                X_sender = np.array(sender_features)
                self.sender_model.scaler.fit(X_sender)
                X_sender_scaled = self.sender_model.scaler.transform(X_sender)
                self.sender_model.model.fit(X_sender_scaled, all_labels)
                self.sender_model.is_trained = True
                logger.info("Sender model trained successfully")
            
            # Content model would be trained here (requires more setup for transformer)
            logger.info("Content model training skipped (requires GPU setup)")
            
            # Calculate metrics
            metrics = await self._evaluate_ensemble(all_samples, all_labels)
            self.last_metrics = metrics
            self.metrics_history.append(metrics)
            
            # Update model version
            self.model_version = f"1.{len(self.metrics_history)}.0"
            
            # Save models if MLflow is available
            if MLFLOW_AVAILABLE:
                await self._save_models_mlflow(metrics)
            
            training_time = (datetime.now() - start_time).total_seconds()
            logger.info(f"Ensemble training completed in {training_time:.2f} seconds")
            logger.info(f"Model metrics - Accuracy: {metrics.accuracy:.3f}, F1: {metrics.f1_score:.3f}")
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error during ensemble training: {e}")
            raise
    
    async def predict_with_explanation(self, email_data: Dict) -> EnsembleResult:
        """Make prediction with full explanation."""
        start_time = datetime.now()
        
        try:
            individual_predictions = {}
            
            # Content model prediction
            if self.content_model and self.content_model.is_initialized:
                content = email_data.get('content', '') + ' ' + email_data.get('subject', '')
                content_pred, content_conf = self.content_model.predict(content)
                individual_predictions['content'] = content_pred
            else:
                individual_predictions['content'] = 0.5
            
            # URL model prediction
            if 'urls' in email_data and email_data['urls'] and self.url_model.is_trained:
                url_pred, url_conf = self.url_model.predict(email_data['urls'][0])
                individual_predictions['url'] = url_pred
            else:
                individual_predictions['url'] = 0.5
            
            # Sender model prediction
            if self.sender_model.is_trained:
                sender = email_data.get('sender', 'unknown@example.com')
                sender_hist = email_data.get('sender_history', {})
                sender_pred, sender_conf = self.sender_model.predict(sender, sender_hist)
                individual_predictions['sender'] = sender_pred
            else:
                individual_predictions['sender'] = 0.5
            
            # Ensemble prediction
            ensemble_score = sum(
                self.ensemble_weights[model] * pred 
                for model, pred in individual_predictions.items()
            )
            
            confidence = min(max(ensemble_score, 0.0), 1.0)
            is_phishing = confidence > 0.5
            risk_score = confidence
            
            # Generate explanation
            explanation = self._generate_ensemble_explanation(
                individual_predictions, ensemble_score, email_data
            )
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return EnsembleResult(
                is_phishing=is_phishing,
                confidence=confidence,
                risk_score=risk_score,
                individual_predictions=individual_predictions,
                explanation=explanation,
                processing_time_ms=processing_time
            )
            
        except Exception as e:
            logger.error(f"Error in ensemble prediction: {e}")
            # Return safe default
            return EnsembleResult(
                is_phishing=False,
                confidence=0.5,
                risk_score=0.5,
                individual_predictions={'content': 0.5, 'url': 0.5, 'sender': 0.5},
                explanation=PredictionExplanation(
                    prediction=0.5,
                    confidence=0.5,
                    top_features=[],
                    explanation_text="Error in prediction",
                    model_used="ensemble"
                ),
                processing_time_ms=0.0
            )
    
    def _generate_ensemble_explanation(self, predictions: Dict[str, float], 
                                     ensemble_score: float, email_data: Dict) -> PredictionExplanation:
        """Generate explanation for ensemble prediction."""
        
        # Calculate feature contributions
        top_features = []
        
        for model, score in predictions.items():
            weight = self.ensemble_weights[model]
            contribution = weight * score
            
            if model == 'content':
                if score > 0.7:
                    top_features.append(('Suspicious content patterns', contribution))
                elif score < 0.3:
                    top_features.append(('Legitimate content patterns', -contribution))
                    
            elif model == 'url':
                if score > 0.7:
                    top_features.append(('Malicious URL indicators', contribution))
                elif score < 0.3:
                    top_features.append(('Trusted URL patterns', -contribution))
                    
            elif model == 'sender':
                if score > 0.7:
                    top_features.append(('Suspicious sender behavior', contribution))
                elif score < 0.3:
                    top_features.append(('Trusted sender history', -contribution))
        
        # Sort by absolute contribution
        top_features.sort(key=lambda x: abs(x[1]), reverse=True)
        top_features = top_features[:5]  # Top 5 features
        
        # Generate explanation text
        if ensemble_score > 0.7:
            explanation_text = f"HIGH RISK: Multiple indicators suggest phishing (confidence: {ensemble_score:.1%})"
        elif ensemble_score > 0.5:
            explanation_text = f"MEDIUM RISK: Some suspicious patterns detected (confidence: {ensemble_score:.1%})"
        else:
            explanation_text = f"LOW RISK: Email appears legitimate (confidence: {1-ensemble_score:.1%})"
        
        return PredictionExplanation(
            prediction=ensemble_score,
            confidence=max(ensemble_score, 1 - ensemble_score),
            top_features=top_features,
            explanation_text=explanation_text,
            model_used="ensemble",
            explanation_method="weighted_ensemble"
        )
    
    async def _evaluate_ensemble(self, test_data: List[Dict], test_labels: List[int]) -> ModelMetrics:
        """Evaluate ensemble performance."""
        
        predictions = []
        true_labels = test_labels
        
        for email_data in test_data:
            result = await self.predict_with_explanation(email_data)
            predictions.append(1 if result.is_phishing else 0)
        
        # Calculate metrics
        predictions = np.array(predictions)
        true_labels = np.array(true_labels)
        
        accuracy = accuracy_score(true_labels, predictions)
        precision = precision_score(true_labels, predictions, zero_division=0)
        recall = recall_score(true_labels, predictions, zero_division=0)
        f1 = f1_score(true_labels, predictions, zero_division=0)
        
        # Calculate rates
        tn = np.sum((true_labels == 0) & (predictions == 0))
        fp = np.sum((true_labels == 0) & (predictions == 1))
        fn = np.sum((true_labels == 1) & (predictions == 0))
        tp = np.sum((true_labels == 1) & (predictions == 1))
        
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        auc_roc = 0.5  # Placeholder - would calculate with prediction probabilities
        
        return ModelMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            auc_roc=auc_roc,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            timestamp=datetime.now(),
            model_version=self.model_version,
            dataset_size=len(test_data)
        )
    
    async def _save_models_mlflow(self, metrics: ModelMetrics):
        """Save models to MLflow registry."""
        if not MLFLOW_AVAILABLE:
            return
        
        try:
            with mlflow.start_run():
                # Log metrics
                mlflow.log_metrics({
                    'accuracy': metrics.accuracy,
                    'precision': metrics.precision,
                    'recall': metrics.recall,
                    'f1_score': metrics.f1_score,
                    'auc_roc': metrics.auc_roc,
                    'fpr': metrics.false_positive_rate,
                    'fnr': metrics.false_negative_rate
                })
                
                # Log parameters
                mlflow.log_params({
                    'model_version': self.model_version,
                    'ensemble_weights': str(self.ensemble_weights),
                    'dataset_size': metrics.dataset_size
                })
                
                # Save models
                if self.url_model.is_trained:
                    mlflow.sklearn.log_model(
                        self.url_model.model,
                        "url_model",
                        registered_model_name="phishnet_url_model"
                    )
                
                if self.sender_model.is_trained:
                    mlflow.sklearn.log_model(
                        self.sender_model.model,
                        "sender_model",
                        registered_model_name="phishnet_sender_model"
                    )
                
                logger.info(f"Models saved to MLflow with version {self.model_version}")
                
        except Exception as e:
            logger.error(f"Error saving models to MLflow: {e}")
    
    def add_analyst_correction(self, email_data: Dict, correct_label: int, 
                             model_prediction: float, user_id: str):
        """Add analyst correction for active learning."""
        self.active_learning.add_correction(email_data, correct_label, model_prediction, user_id)
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get comprehensive model status."""
        return {
            'model_version': self.model_version,
            'ensemble_weights': self.ensemble_weights,
            'models_trained': {
                'content': self.content_model.is_initialized if self.content_model else False,
                'url': self.url_model.is_trained,
                'sender': self.sender_model.is_trained
            },
            'last_metrics': asdict(self.last_metrics) if self.last_metrics else None,
            'active_learning_queue_size': len(self.active_learning.correction_queue),
            'next_retrain_due': self.active_learning.should_retrain(),
            'pytorch_available': PYTORCH_AVAILABLE,
            'explainability_available': EXPLAINABILITY_AVAILABLE,
            'mlflow_available': MLFLOW_AVAILABLE
        }


# Global instance
advanced_ml_system = AdvancedEnsembleML()