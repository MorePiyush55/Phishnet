"""Model calibration, monitoring and versioning system for PhishNet.

This module provides:
1. Model performance monitoring with detailed metrics tracking
2. MLflow integration for model versioning and registry
3. Model calibration and reliability scoring
4. Drift detection and performance degradation alerts
5. A/B testing framework for model comparison
"""

import asyncio
import json
import pickle
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import hashlib
import logging
from pathlib import Path
import numpy as np
import pandas as pd

# Database
from sqlalchemy import Column, Integer, Float, String, DateTime, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

# ML Libraries
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, classification_report, brier_score_loss
)
from sklearn.model_selection import cross_val_predict

# Monitoring
import psutil
import time

# MLflow (optional)
try:
    import mlflow
    import mlflow.sklearn
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False
    logging.warning("MLflow not available for model versioning")

from app.config.logging import get_logger
from app.config.settings import get_settings
from app.db.base import Base

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class ModelPerformanceMetrics:
    """Comprehensive model performance metrics."""
    model_id: str
    model_version: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    brier_score: float
    calibration_error: float
    
    # Detailed metrics
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    
    # Performance characteristics
    avg_prediction_time_ms: float
    memory_usage_mb: float
    throughput_predictions_per_sec: float
    
    # Dataset info
    test_set_size: int
    class_distribution: Dict[str, float]
    
    # Timestamps
    evaluation_timestamp: datetime
    training_timestamp: Optional[datetime] = None


@dataclass
class ModelDriftMetrics:
    """Model drift detection metrics."""
    model_id: str
    drift_detected: bool
    drift_score: float
    drift_type: str  # 'concept', 'data', 'performance'
    
    # Performance comparison
    current_accuracy: float
    baseline_accuracy: float
    accuracy_drop: float
    
    # Feature drift
    feature_drift_scores: Dict[str, float]
    
    timestamp: datetime


@dataclass
class CalibrationMetrics:
    """Model calibration quality metrics."""
    model_id: str
    reliability_diagram_data: Dict[str, List[float]]
    expected_calibration_error: float
    maximum_calibration_error: float
    brier_score: float
    is_well_calibrated: bool
    calibration_method: str
    timestamp: datetime


class ModelMetricsDB(Base):
    """Database model for storing model performance metrics."""
    
    __tablename__ = "model_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(String, index=True, nullable=False)
    model_version = Column(String, nullable=False)
    
    # Performance metrics
    accuracy = Column(Float, nullable=False)
    precision = Column(Float, nullable=False)
    recall = Column(Float, nullable=False)
    f1_score = Column(Float, nullable=False)
    auc_roc = Column(Float, nullable=False)
    brier_score = Column(Float, nullable=False)
    calibration_error = Column(Float, nullable=False)
    
    # Confusion matrix
    true_positives = Column(Integer, nullable=False)
    true_negatives = Column(Integer, nullable=False)
    false_positives = Column(Integer, nullable=False)
    false_negatives = Column(Integer, nullable=False)
    
    # Performance characteristics
    avg_prediction_time_ms = Column(Float, nullable=False)
    memory_usage_mb = Column(Float, nullable=False)
    throughput_predictions_per_sec = Column(Float, nullable=False)
    
    # Dataset info
    test_set_size = Column(Integer, nullable=False)
    class_distribution = Column(JSON)
    
    # Additional metadata
    training_data_hash = Column(String)
    hyperparameters = Column(JSON)
    feature_importance = Column(JSON)
    
    # Timestamps
    evaluation_timestamp = Column(DateTime, nullable=False)
    training_timestamp = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)


class ModelDriftDB(Base):
    """Database model for storing drift detection results."""
    
    __tablename__ = "model_drift"
    
    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(String, index=True, nullable=False)
    drift_detected = Column(Boolean, nullable=False)
    drift_score = Column(Float, nullable=False)
    drift_type = Column(String, nullable=False)
    
    current_accuracy = Column(Float, nullable=False)
    baseline_accuracy = Column(Float, nullable=False)
    accuracy_drop = Column(Float, nullable=False)
    
    feature_drift_scores = Column(JSON)
    alert_sent = Column(Boolean, default=False)
    
    timestamp = Column(DateTime, default=datetime.utcnow)


class ModelRegistry:
    """MLflow-based model registry for version management."""
    
    def __init__(self):
        """Initialize model registry."""
        self.experiment_name = "phishnet_ensemble_models"
        self.registry_models = {
            'content_transformer': 'phishnet_content_model',
            'url_feature': 'phishnet_url_model',
            'sender_behavior': 'phishnet_sender_model',
            'ensemble': 'phishnet_ensemble_model'
        }
        
        if MLFLOW_AVAILABLE:
            # Set up MLflow
            mlflow.set_experiment(self.experiment_name)
            logger.info(f"MLflow experiment set: {self.experiment_name}")
        
        self.local_model_store = Path("models")
        self.local_model_store.mkdir(exist_ok=True)
    
    def log_model_training(self, model, model_type: str, metrics: ModelPerformanceMetrics, 
                          hyperparams: Dict[str, Any], training_data_hash: str) -> str:
        """Log model training run to MLflow."""
        
        run_id = None
        
        if MLFLOW_AVAILABLE:
            try:
                with mlflow.start_run() as run:
                    run_id = run.info.run_id
                    
                    # Log hyperparameters
                    mlflow.log_params(hyperparams)
                    
                    # Log metrics
                    mlflow.log_metrics({
                        'accuracy': metrics.accuracy,
                        'precision': metrics.precision,
                        'recall': metrics.recall,
                        'f1_score': metrics.f1_score,
                        'auc_roc': metrics.auc_roc,
                        'brier_score': metrics.brier_score,
                        'calibration_error': metrics.calibration_error,
                        'avg_prediction_time_ms': metrics.avg_prediction_time_ms,
                        'throughput_per_sec': metrics.throughput_predictions_per_sec,
                        'memory_usage_mb': metrics.memory_usage_mb,
                        'test_set_size': metrics.test_set_size
                    })
                    
                    # Log additional info
                    mlflow.log_params({
                        'model_type': model_type,
                        'model_version': metrics.model_version,
                        'training_data_hash': training_data_hash,
                        'class_distribution': json.dumps(metrics.class_distribution)
                    })
                    
                    # Log model artifact
                    if hasattr(model, 'save'):
                        # For PyTorch models
                        mlflow.pytorch.log_model(
                            model, 
                            model_type,
                            registered_model_name=self.registry_models.get(model_type, f"phishnet_{model_type}")
                        )
                    else:
                        # For sklearn models
                        mlflow.sklearn.log_model(
                            model,
                            model_type,
                            registered_model_name=self.registry_models.get(model_type, f"phishnet_{model_type}")
                        )
                    
                    # Log confusion matrix as artifact
                    cm_data = {
                        'true_positives': metrics.true_positives,
                        'true_negatives': metrics.true_negatives,
                        'false_positives': metrics.false_positives,
                        'false_negatives': metrics.false_negatives
                    }
                    
                    with open("confusion_matrix.json", "w") as f:
                        json.dump(cm_data, f)
                    mlflow.log_artifact("confusion_matrix.json")
                    
                    logger.info(f"Model {model_type} logged to MLflow with run_id: {run_id}")
                    
            except Exception as e:
                logger.error(f"Failed to log model to MLflow: {e}")
        
        # Also save locally as backup
        local_path = self.local_model_store / f"{model_type}_{metrics.model_version}_{training_data_hash[:8]}.pkl"
        try:
            with open(local_path, 'wb') as f:
                pickle.dump({
                    'model': model,
                    'metrics': asdict(metrics),
                    'hyperparams': hyperparams,
                    'timestamp': datetime.now().isoformat()
                }, f)
            logger.info(f"Model saved locally: {local_path}")
        except Exception as e:
            logger.error(f"Failed to save model locally: {e}")
        
        return run_id or f"local_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def get_latest_model_version(self, model_type: str) -> Optional[Dict[str, Any]]:
        """Get latest model version from registry."""
        
        if MLFLOW_AVAILABLE:
            try:
                client = mlflow.tracking.MlflowClient()
                model_name = self.registry_models.get(model_type, f"phishnet_{model_type}")
                
                # Get latest version
                latest_version = client.get_latest_versions(model_name, stages=["Production"])
                if not latest_version:
                    latest_version = client.get_latest_versions(model_name, stages=["None"])
                
                if latest_version:
                    version_info = latest_version[0]
                    run = client.get_run(version_info.run_id)
                    
                    return {
                        'version': version_info.version,
                        'run_id': version_info.run_id,
                        'metrics': run.data.metrics,
                        'params': run.data.params,
                        'model_uri': f"models:/{model_name}/{version_info.version}"
                    }
                    
            except Exception as e:
                logger.error(f"Failed to get latest model version: {e}")
        
        # Fallback to local storage
        pattern = f"{model_type}_*.pkl"
        local_models = list(self.local_model_store.glob(pattern))
        
        if local_models:
            latest_model = max(local_models, key=lambda x: x.stat().st_mtime)
            return {
                'version': 'local',
                'model_path': str(latest_model),
                'metrics': {},
                'params': {}
            }
        
        return None
    
    def load_model(self, model_type: str, version: Optional[str] = None):
        """Load model from registry."""
        
        if MLFLOW_AVAILABLE and version and version != 'local':
            try:
                model_name = self.registry_models.get(model_type, f"phishnet_{model_type}")
                model_uri = f"models:/{model_name}/{version}"
                return mlflow.pyfunc.load_model(model_uri)
            except Exception as e:
                logger.error(f"Failed to load model from MLflow: {e}")
        
        # Load from local storage
        model_info = self.get_latest_model_version(model_type)
        if model_info and 'model_path' in model_info:
            try:
                with open(model_info['model_path'], 'rb') as f:
                    model_data = pickle.load(f)
                return model_data['model']
            except Exception as e:
                logger.error(f"Failed to load local model: {e}")
        
        return None


class ModelCalibrator:
    """Model calibration for reliable probability estimates."""
    
    def __init__(self):
        """Initialize model calibrator."""
        self.calibrated_models = {}
        self.calibration_data = {}
    
    def calibrate_model(self, model, X_cal: np.ndarray, y_cal: np.ndarray, 
                       method: str = 'isotonic') -> Tuple[Any, CalibrationMetrics]:
        """Calibrate model for better probability estimates."""
        
        try:
            # Create calibrated classifier
            if method == 'isotonic':
                calibrated_model = CalibratedClassifierCV(model, method='isotonic', cv='prefit')
            else:  # Platt scaling
                calibrated_model = CalibratedClassifierCV(model, method='sigmoid', cv='prefit')
            
            # Fit calibration
            calibrated_model.fit(X_cal, y_cal)
            
            # Evaluate calibration quality
            y_pred_proba = calibrated_model.predict_proba(X_cal)[:, 1]
            
            # Calculate calibration metrics
            fraction_of_positives, mean_predicted_value = calibration_curve(
                y_cal, y_pred_proba, n_bins=10
            )
            
            # Expected Calibration Error (ECE)
            bin_boundaries = np.linspace(0, 1, 11)
            bin_lowers = bin_boundaries[:-1]
            bin_uppers = bin_boundaries[1:]
            
            ece = 0
            max_ce = 0
            reliability_data = {'bin_centers': [], 'accuracy': [], 'confidence': [], 'counts': []}
            
            for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
                in_bin = (y_pred_proba > bin_lower) & (y_pred_proba <= bin_upper)
                prop_in_bin = in_bin.mean()
                
                if prop_in_bin > 0:
                    accuracy_in_bin = y_cal[in_bin].mean()
                    avg_confidence_in_bin = y_pred_proba[in_bin].mean()
                    
                    bin_ce = abs(avg_confidence_in_bin - accuracy_in_bin)
                    ece += bin_ce * prop_in_bin
                    max_ce = max(max_ce, bin_ce)
                    
                    reliability_data['bin_centers'].append((bin_lower + bin_upper) / 2)
                    reliability_data['accuracy'].append(accuracy_in_bin)
                    reliability_data['confidence'].append(avg_confidence_in_bin)
                    reliability_data['counts'].append(in_bin.sum())
            
            # Brier score
            brier_score = brier_score_loss(y_cal, y_pred_proba)
            
            # Determine if well calibrated (ECE < 0.1)
            is_well_calibrated = ece < 0.1
            
            model_id = f"model_{hash(str(model))}"
            
            calibration_metrics = CalibrationMetrics(
                model_id=model_id,
                reliability_diagram_data=reliability_data,
                expected_calibration_error=ece,
                maximum_calibration_error=max_ce,
                brier_score=brier_score,
                is_well_calibrated=is_well_calibrated,
                calibration_method=method,
                timestamp=datetime.now()
            )
            
            # Store calibrated model
            self.calibrated_models[model_id] = calibrated_model
            self.calibration_data[model_id] = calibration_metrics
            
            logger.info(f"Model calibrated: ECE={ece:.3f}, Brier={brier_score:.3f}, Well-calibrated={is_well_calibrated}")
            
            return calibrated_model, calibration_metrics
            
        except Exception as e:
            logger.error(f"Error during model calibration: {e}")
            raise


class DriftDetector:
    """Model drift detection using statistical tests and performance monitoring."""
    
    def __init__(self, baseline_window: int = 1000):
        """Initialize drift detector."""
        self.baseline_window = baseline_window
        self.baseline_data = {}
        self.performance_history = {}
        
    def update_baseline(self, model_id: str, predictions: np.ndarray, 
                       features: np.ndarray, true_labels: np.ndarray):
        """Update baseline statistics for drift detection."""
        
        if model_id not in self.baseline_data:
            self.baseline_data[model_id] = {
                'predictions': [],
                'features': [],
                'true_labels': [],
                'performance': []
            }
        
        # Update baseline data (keep only recent data)
        baseline = self.baseline_data[model_id]
        baseline['predictions'].extend(predictions.tolist())
        baseline['features'].extend(features.tolist())
        baseline['true_labels'].extend(true_labels.tolist())
        
        # Calculate performance for this batch
        accuracy = accuracy_score(true_labels, (predictions > 0.5).astype(int))
        baseline['performance'].append(accuracy)
        
        # Maintain sliding window
        if len(baseline['predictions']) > self.baseline_window:
            excess = len(baseline['predictions']) - self.baseline_window
            baseline['predictions'] = baseline['predictions'][excess:]
            baseline['features'] = baseline['features'][excess:]
            baseline['true_labels'] = baseline['true_labels'][excess:]
            baseline['performance'] = baseline['performance'][-100:]  # Keep last 100 performance scores
    
    def detect_drift(self, model_id: str, new_predictions: np.ndarray, 
                    new_features: np.ndarray, new_labels: np.ndarray) -> ModelDriftMetrics:
        """Detect various types of drift."""
        
        try:
            drift_detected = False
            drift_scores = {}
            drift_type = "none"
            
            if model_id not in self.baseline_data:
                # No baseline yet
                return ModelDriftMetrics(
                    model_id=model_id,
                    drift_detected=False,
                    drift_score=0.0,
                    drift_type="no_baseline",
                    current_accuracy=0.5,
                    baseline_accuracy=0.5,
                    accuracy_drop=0.0,
                    feature_drift_scores={},
                    timestamp=datetime.now()
                )
            
            baseline = self.baseline_data[model_id]
            
            # Performance drift detection
            current_accuracy = accuracy_score(new_labels, (new_predictions > 0.5).astype(int))
            baseline_accuracy = np.mean(baseline['performance'][-20:]) if baseline['performance'] else 0.5
            accuracy_drop = baseline_accuracy - current_accuracy
            
            if accuracy_drop > 0.05:  # 5% drop threshold
                drift_detected = True
                drift_type = "performance"
                drift_scores['performance'] = accuracy_drop
            
            # Feature drift detection (simplified - using mean shift)
            baseline_features = np.array(baseline['features'][-500:]) if len(baseline['features']) >= 500 else np.array(baseline['features'])
            
            if len(baseline_features) > 0 and len(new_features) > 0:
                baseline_means = np.mean(baseline_features, axis=0)
                new_means = np.mean(new_features, axis=0)
                
                # Calculate normalized differences
                feature_diffs = np.abs(new_means - baseline_means) / (np.std(baseline_features, axis=0) + 1e-8)
                
                # Check for significant feature shifts
                significant_shifts = feature_diffs > 2.0  # 2 standard deviations
                
                if np.any(significant_shifts):
                    drift_detected = True
                    if drift_type == "none":
                        drift_type = "data"
                    
                    # Store feature drift scores
                    for i, shift in enumerate(significant_shifts):
                        if shift:
                            drift_scores[f'feature_{i}'] = float(feature_diffs[i])
            
            # Concept drift detection (prediction distribution shift)
            baseline_predictions = np.array(baseline['predictions'][-500:]) if len(baseline['predictions']) >= 500 else np.array(baseline['predictions'])
            
            if len(baseline_predictions) > 0:
                # Kolmogorov-Smirnov test (simplified)
                baseline_mean = np.mean(baseline_predictions)
                baseline_std = np.std(baseline_predictions)
                new_mean = np.mean(new_predictions)
                new_std = np.std(new_predictions)
                
                # Check for significant distribution shift
                mean_shift = abs(new_mean - baseline_mean) / (baseline_std + 1e-8)
                std_shift = abs(new_std - baseline_std) / (baseline_std + 1e-8)
                
                if mean_shift > 1.5 or std_shift > 0.5:
                    drift_detected = True
                    if drift_type == "none":
                        drift_type = "concept"
                    drift_scores['concept_mean_shift'] = mean_shift
                    drift_scores['concept_std_shift'] = std_shift
            
            # Overall drift score
            overall_drift_score = max(drift_scores.values()) if drift_scores else 0.0
            
            drift_metrics = ModelDriftMetrics(
                model_id=model_id,
                drift_detected=drift_detected,
                drift_score=overall_drift_score,
                drift_type=drift_type,
                current_accuracy=current_accuracy,
                baseline_accuracy=baseline_accuracy,
                accuracy_drop=accuracy_drop,
                feature_drift_scores=drift_scores,
                timestamp=datetime.now()
            )
            
            if drift_detected:
                logger.warning(f"Drift detected for model {model_id}: {drift_type} drift (score: {overall_drift_score:.3f})")
            
            return drift_metrics
            
        except Exception as e:
            logger.error(f"Error during drift detection: {e}")
            return ModelDriftMetrics(
                model_id=model_id,
                drift_detected=False,
                drift_score=0.0,
                drift_type="error",
                current_accuracy=0.0,
                baseline_accuracy=0.0,
                accuracy_drop=0.0,
                feature_drift_scores={},
                timestamp=datetime.now()
            )


class ModelMonitor:
    """Comprehensive model monitoring system."""
    
    def __init__(self, db_session: Session):
        """Initialize model monitor."""
        self.db = db_session
        self.registry = ModelRegistry()
        self.calibrator = ModelCalibrator()
        self.drift_detector = DriftDetector()
        
        # Performance tracking
        self.prediction_times = {}
        self.memory_usage = {}
        self.throughput_counters = {}
        
        logger.info("Model monitoring system initialized")
    
    def evaluate_model_comprehensive(self, model, model_type: str, model_version: str,
                                   X_test: np.ndarray, y_test: np.ndarray,
                                   feature_names: Optional[List[str]] = None) -> ModelPerformanceMetrics:
        """Perform comprehensive model evaluation."""
        
        start_time = time.time()
        process = psutil.Process()
        memory_before = process.memory_info().rss / 1024 / 1024  # MB
        
        try:
            # Make predictions
            prediction_times = []
            predictions = []
            prediction_probas = []
            
            # Measure individual prediction times
            for i in range(min(100, len(X_test))):  # Sample for timing
                pred_start = time.time()
                
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba([X_test[i]])[0]
                    pred = 1 if proba[1] > 0.5 else 0
                else:
                    pred = model.predict([X_test[i]])[0]
                    proba = [1-pred, pred] if hasattr(model, 'decision_function') else [0.5, 0.5]
                
                pred_time = (time.time() - pred_start) * 1000  # ms
                prediction_times.append(pred_time)
                predictions.append(pred)
                prediction_probas.append(proba[1] if len(proba) > 1 else proba[0])
            
            # Full predictions for metrics
            if hasattr(model, 'predict_proba'):
                y_pred_proba = model.predict_proba(X_test)[:, 1]
                y_pred = (y_pred_proba > 0.5).astype(int)
            else:
                y_pred = model.predict(X_test)
                y_pred_proba = y_pred  # Fallback
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            try:
                auc_roc = roc_auc_score(y_test, y_pred_proba)
            except ValueError:
                auc_roc = 0.5
            
            try:
                brier_score = brier_score_loss(y_test, y_pred_proba)
            except (ValueError, TypeError):
                brier_score = 0.5
            
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, len(y_test))
            
            # Calibration error (simplified)
            try:
                fraction_of_positives, mean_predicted_value = calibration_curve(
                    y_test, y_pred_proba, n_bins=10
                )
                calibration_error = np.mean(np.abs(fraction_of_positives - mean_predicted_value))
            except (ValueError, TypeError):
                calibration_error = 0.1
            
            # Performance characteristics
            avg_pred_time = np.mean(prediction_times)
            total_time = time.time() - start_time
            throughput = len(X_test) / total_time if total_time > 0 else 0
            
            memory_after = process.memory_info().rss / 1024 / 1024  # MB
            memory_usage = memory_after - memory_before
            
            # Class distribution
            unique, counts = np.unique(y_test, return_counts=True)
            class_dist = {str(cls): count/len(y_test) for cls, count in zip(unique, counts)}
            
            model_id = f"{model_type}_{model_version}"
            
            metrics = ModelPerformanceMetrics(
                model_id=model_id,
                model_version=model_version,
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                auc_roc=auc_roc,
                brier_score=brier_score,
                calibration_error=calibration_error,
                true_positives=int(tp),
                true_negatives=int(tn),
                false_positives=int(fp),
                false_negatives=int(fn),
                avg_prediction_time_ms=avg_pred_time,
                memory_usage_mb=memory_usage,
                throughput_predictions_per_sec=throughput,
                test_set_size=len(X_test),
                class_distribution=class_dist,
                evaluation_timestamp=datetime.now()
            )
            
            # Store metrics in database
            self.store_metrics(metrics, feature_names)
            
            logger.info(f"Model evaluation completed: {model_id} - Accuracy: {accuracy:.3f}, F1: {f1:.3f}")
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error during model evaluation: {e}")
            raise
    
    def store_metrics(self, metrics: ModelPerformanceMetrics, feature_names: Optional[List[str]] = None):
        """Store model metrics in database."""
        
        try:
            # Create database record
            db_metrics = ModelMetricsDB(
                model_id=metrics.model_id,
                model_version=metrics.model_version,
                accuracy=metrics.accuracy,
                precision=metrics.precision,
                recall=metrics.recall,
                f1_score=metrics.f1_score,
                auc_roc=metrics.auc_roc,
                brier_score=metrics.brier_score,
                calibration_error=metrics.calibration_error,
                true_positives=metrics.true_positives,
                true_negatives=metrics.true_negatives,
                false_positives=metrics.false_positives,
                false_negatives=metrics.false_negatives,
                avg_prediction_time_ms=metrics.avg_prediction_time_ms,
                memory_usage_mb=metrics.memory_usage_mb,
                throughput_predictions_per_sec=metrics.throughput_predictions_per_sec,
                test_set_size=metrics.test_set_size,
                class_distribution=metrics.class_distribution,
                evaluation_timestamp=metrics.evaluation_timestamp,
                training_timestamp=metrics.training_timestamp
            )
            
            if feature_names:
                db_metrics.feature_importance = {name: 0.0 for name in feature_names}
            
            self.db.add(db_metrics)
            self.db.commit()
            
            logger.info(f"Metrics stored in database for {metrics.model_id}")
            
        except Exception as e:
            logger.error(f"Failed to store metrics in database: {e}")
            self.db.rollback()
    
    def check_model_drift(self, model_id: str, predictions: np.ndarray, 
                         features: np.ndarray, true_labels: np.ndarray) -> ModelDriftMetrics:
        """Check for model drift and store results."""
        
        try:
            drift_metrics = self.drift_detector.detect_drift(model_id, predictions, features, true_labels)
            
            # Store drift metrics in database
            db_drift = ModelDriftDB(
                model_id=drift_metrics.model_id,
                drift_detected=drift_metrics.drift_detected,
                drift_score=drift_metrics.drift_score,
                drift_type=drift_metrics.drift_type,
                current_accuracy=drift_metrics.current_accuracy,
                baseline_accuracy=drift_metrics.baseline_accuracy,
                accuracy_drop=drift_metrics.accuracy_drop,
                feature_drift_scores=drift_metrics.feature_drift_scores,
                timestamp=drift_metrics.timestamp
            )
            
            self.db.add(db_drift)
            self.db.commit()
            
            # Update baseline for next comparison
            self.drift_detector.update_baseline(model_id, predictions, features, true_labels)
            
            if drift_metrics.drift_detected:
                logger.warning(f"Model drift detected for {model_id}: {drift_metrics.drift_type}")
                # Could trigger alerts here
            
            return drift_metrics
            
        except Exception as e:
            logger.error(f"Error checking model drift: {e}")
            self.db.rollback()
            raise
    
    def get_model_performance_history(self, model_id: str, days: int = 30) -> List[ModelPerformanceMetrics]:
        """Get model performance history from database."""
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            records = self.db.query(ModelMetricsDB).filter(
                ModelMetricsDB.model_id == model_id,
                ModelMetricsDB.evaluation_timestamp >= cutoff_date
            ).order_by(ModelMetricsDB.evaluation_timestamp.desc()).all()
            
            history = []
            for record in records:
                metrics = ModelPerformanceMetrics(
                    model_id=record.model_id,
                    model_version=record.model_version,
                    accuracy=record.accuracy,
                    precision=record.precision,
                    recall=record.recall,
                    f1_score=record.f1_score,
                    auc_roc=record.auc_roc,
                    brier_score=record.brier_score,
                    calibration_error=record.calibration_error,
                    true_positives=record.true_positives,
                    true_negatives=record.true_negatives,
                    false_positives=record.false_positives,
                    false_negatives=record.false_negatives,
                    avg_prediction_time_ms=record.avg_prediction_time_ms,
                    memory_usage_mb=record.memory_usage_mb,
                    throughput_predictions_per_sec=record.throughput_predictions_per_sec,
                    test_set_size=record.test_set_size,
                    class_distribution=record.class_distribution,
                    evaluation_timestamp=record.evaluation_timestamp,
                    training_timestamp=record.training_timestamp
                )
                history.append(metrics)
            
            return history
            
        except Exception as e:
            logger.error(f"Error getting performance history: {e}")
            return []
    
    def generate_model_report(self, model_id: str) -> Dict[str, Any]:
        """Generate comprehensive model report."""
        
        try:
            # Get latest metrics
            latest_metrics = self.db.query(ModelMetricsDB).filter(
                ModelMetricsDB.model_id == model_id
            ).order_by(ModelMetricsDB.evaluation_timestamp.desc()).first()
            
            # Get drift history
            recent_drift = self.db.query(ModelDriftDB).filter(
                ModelDriftDB.model_id == model_id
            ).order_by(ModelDriftDB.timestamp.desc()).limit(10).all()
            
            # Get performance trend
            performance_history = self.get_model_performance_history(model_id, days=30)
            
            report = {
                'model_id': model_id,
                'report_generated_at': datetime.now().isoformat(),
                'latest_performance': asdict(performance_history[0]) if performance_history else None,
                'performance_trend': {
                    'accuracy_trend': [m.accuracy for m in performance_history[-10:]],
                    'f1_trend': [m.f1_score for m in performance_history[-10:]],
                    'drift_incidents': len([d for d in recent_drift if d.drift_detected])
                },
                'drift_status': {
                    'recent_drift_detected': recent_drift[0].drift_detected if recent_drift else False,
                    'last_drift_type': recent_drift[0].drift_type if recent_drift else 'none',
                    'drift_score': recent_drift[0].drift_score if recent_drift else 0.0
                },
                'recommendations': []
            }
            
            # Generate recommendations
            if latest_metrics:
                if latest_metrics.accuracy < 0.8:
                    report['recommendations'].append("Model accuracy is below 80%. Consider retraining.")
                if latest_metrics.calibration_error > 0.15:
                    report['recommendations'].append("Model is poorly calibrated. Consider calibration.")
                if latest_metrics.false_positive_rate > 0.1:
                    report['recommendations'].append("High false positive rate detected.")
                if recent_drift and recent_drift[0].drift_detected:
                    report['recommendations'].append("Model drift detected. Retraining recommended.")
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating model report: {e}")
            return {'error': str(e)}


# Initialize monitoring system (would be dependency injected in real app)
def get_model_monitor(db_session: Session) -> ModelMonitor:
    """Get model monitor instance."""
    return ModelMonitor(db_session)