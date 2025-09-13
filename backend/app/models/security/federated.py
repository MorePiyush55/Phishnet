"""Federated Learning models for client and server management."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, JSON
from sqlalchemy.orm import relationship

from app.core.database import Base


class FederatedClient(Base):
    """Federated Learning client model."""
    
    __tablename__ = "federated_clients"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    client_id = Column(String(100), unique=True, index=True, nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    
    # Client status
    is_active = Column(Boolean, default=True)
    is_online = Column(Boolean, default=False)
    last_seen = Column(DateTime, nullable=True)
    
    # Client capabilities
    data_size = Column(Integer, default=0)  # Number of training samples
    model_version = Column(String(50), nullable=True)
    
    # Performance metrics
    accuracy = Column(Float, nullable=True)
    loss = Column(Float, nullable=True)
    training_time = Column(Integer, nullable=True)  # seconds
    
    # Security
    api_key = Column(String(255), unique=True, nullable=False)
    encryption_key = Column(String(255), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="federated_clients")
    training_rounds = relationship("FederatedTrainingRound", back_populates="client")
    
    def __repr__(self) -> str:
        return f"<FederatedClient(id={self.id}, client_id='{self.client_id}', name='{self.name}')>"


class FederatedTrainingRound(Base):
    """Federated Learning training round model."""
    
    __tablename__ = "federated_training_rounds"
    
    id = Column(Integer, primary_key=True, index=True)
    round_number = Column(Integer, nullable=False, index=True)
    client_id = Column(Integer, nullable=False, index=True)
    
    # Training results
    local_accuracy = Column(Float, nullable=True)
    local_loss = Column(Float, nullable=True)
    global_accuracy = Column(Float, nullable=True)
    global_loss = Column(Float, nullable=True)
    
    # Training metadata
    training_time = Column(Integer, nullable=True)  # seconds
    data_samples = Column(Integer, nullable=True)
    model_updates = Column(JSON, nullable=True)  # Model weight updates
    
    # Round status
    status = Column(String(20), default="pending")  # pending, training, completed, failed
    error_message = Column(Text, nullable=True)
    
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    # Relationships
    client = relationship("FederatedClient", back_populates="training_rounds")
    
    def __repr__(self) -> str:
        return f"<FederatedTrainingRound(id={self.id}, round={self.round_number}, status='{self.status}')>"


class FederatedModel(Base):
    """Federated Learning global model model."""
    
    __tablename__ = "federated_models"
    
    id = Column(Integer, primary_key=True, index=True)
    version = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    
    # Model performance
    accuracy = Column(Float, nullable=True)
    loss = Column(Float, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    
    # Model metadata
    model_path = Column(String(500), nullable=False)
    model_size_bytes = Column(Integer, nullable=True)
    parameters_count = Column(Integer, nullable=True)
    
    # Training metadata
    total_rounds = Column(Integer, default=0)
    total_clients = Column(Integer, default=0)
    total_samples = Column(Integer, default=0)
    
    # Model status
    is_active = Column(Boolean, default=False)
    is_deployed = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    deployed_at = Column(DateTime, nullable=True)
    
    def __repr__(self) -> str:
        return f"<FederatedModel(id={self.id}, version='{self.version}', accuracy={self.accuracy})>"

