"""Federated Learning API routes."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.models.federated import FederatedClient, FederatedTrainingRound, FederatedModel
from app.config.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


@router.post("/clients/register")
async def register_client(
    client_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Register a new federated learning client."""
    try:
        # Generate unique client ID and API key
        import secrets
        client_id = f"client_{secrets.token_hex(8)}"
        api_key = secrets.token_hex(32)
        
        client = FederatedClient(
            user_id=current_user.id,
            client_id=client_id,
            name=client_data.get("name", "Unnamed Client"),
            description=client_data.get("description"),
            api_key=api_key
        )
        
        db.add(client)
        db.commit()
        db.refresh(client)
        
        logger.info(f"New FL client registered: {client_id}")
        
        return {
            "client_id": client_id,
            "api_key": api_key,
            "message": "Client registered successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to register client: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register client"
        )


@router.get("/clients", response_model=List[dict])
async def get_clients(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's federated learning clients."""
    try:
        clients = db.query(FederatedClient).filter(
            FederatedClient.user_id == current_user.id
        ).all()
        
        return [
            {
                "id": client.id,
                "client_id": client.client_id,
                "name": client.name,
                "description": client.description,
                "is_active": client.is_active,
                "is_online": client.is_online,
                "last_seen": client.last_seen,
                "data_size": client.data_size,
                "model_version": client.model_version,
                "accuracy": client.accuracy,
                "created_at": client.created_at
            }
            for client in clients
        ]
        
    except Exception as e:
        logger.error(f"Failed to get clients: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve clients"
        )


@router.get("/clients/{client_id}/status")
async def get_client_status(
    client_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific client status."""
    client = db.query(FederatedClient).filter(
        FederatedClient.client_id == client_id,
        FederatedClient.user_id == current_user.id
    ).first()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )
    
    return {
        "client_id": client.client_id,
        "name": client.name,
        "is_online": client.is_online,
        "last_seen": client.last_seen,
        "data_size": client.data_size,
        "model_version": client.model_version,
        "accuracy": client.accuracy,
        "loss": client.loss,
        "training_time": client.training_time
    }


@router.post("/clients/{client_id}/heartbeat")
async def client_heartbeat(
    client_id: str,
    heartbeat_data: dict,
    db: Session = Depends(get_db)
):
    """Update client heartbeat and status."""
    # This would typically be called by the client itself
    # For now, we'll simulate it
    client = db.query(FederatedClient).filter(
        FederatedClient.client_id == client_id
    ).first()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )
    
    # Update client status
    client.is_online = True
    client.last_seen = heartbeat_data.get("timestamp")
    client.data_size = heartbeat_data.get("data_size", client.data_size)
    client.model_version = heartbeat_data.get("model_version", client.model_version)
    
    db.commit()
    
    return {"message": "Heartbeat received"}


@router.get("/models", response_model=List[dict])
async def get_federated_models(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get federated learning models."""
    try:
        models = db.query(FederatedModel).filter(
            FederatedModel.is_active == True
        ).order_by(FederatedModel.created_at.desc()).all()
        
        return [
            {
                "id": model.id,
                "version": model.version,
                "name": model.name,
                "description": model.description,
                "accuracy": model.accuracy,
                "loss": model.loss,
                "precision": model.precision,
                "recall": model.recall,
                "f1_score": model.f1_score,
                "total_rounds": model.total_rounds,
                "total_clients": model.total_clients,
                "total_samples": model.total_samples,
                "is_deployed": model.is_deployed,
                "created_at": model.created_at,
                "deployed_at": model.deployed_at
            }
            for model in models
        ]
        
    except Exception as e:
        logger.error(f"Failed to get models: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve models"
        )


@router.get("/training-rounds", response_model=List[dict])
async def get_training_rounds(
    client_id: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get federated learning training rounds."""
    try:
        query = db.query(FederatedTrainingRound)
        
        if client_id:
            # Get client ID from client_id string
            client = db.query(FederatedClient).filter(
                FederatedClient.client_id == client_id,
                FederatedClient.user_id == current_user.id
            ).first()
            if client:
                query = query.filter(FederatedTrainingRound.client_id == client.id)
        
        rounds = query.order_by(FederatedTrainingRound.started_at.desc()).limit(limit).all()
        
        return [
            {
                "id": round.id,
                "round_number": round.round_number,
                "client_id": round.client_id,
                "local_accuracy": round.local_accuracy,
                "local_loss": round.local_loss,
                "global_accuracy": round.global_accuracy,
                "global_loss": round.global_loss,
                "training_time": round.training_time,
                "data_samples": round.data_samples,
                "status": round.status,
                "started_at": round.started_at,
                "completed_at": round.completed_at
            }
            for round in rounds
        ]
        
    except Exception as e:
        logger.error(f"Failed to get training rounds: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve training rounds"
        )


@router.post("/training/start")
async def start_training_round(
    training_config: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start a new federated learning training round."""
    try:
        # This would typically coordinate with multiple clients
        # For now, we'll create a placeholder training round
        
        # Get the latest round number
        latest_round = db.query(FederatedTrainingRound).order_by(
            FederatedTrainingRound.round_number.desc()
        ).first()
        
        round_number = (latest_round.round_number + 1) if latest_round else 1
        
        # Create training round
        training_round = FederatedTrainingRound(
            round_number=round_number,
            client_id=1,  # Placeholder
            status="pending"
        )
        
        db.add(training_round)
        db.commit()
        
        logger.info(f"Started FL training round: {round_number}")
        
        return {
            "round_number": round_number,
            "status": "started",
            "message": "Training round initiated"
        }
        
    except Exception as e:
        logger.error(f"Failed to start training round: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start training round"
        )


@router.get("/stats")
async def get_federated_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get federated learning statistics."""
    try:
        # Get client stats
        total_clients = db.query(FederatedClient).filter(
            FederatedClient.user_id == current_user.id
        ).count()
        
        active_clients = db.query(FederatedClient).filter(
            FederatedClient.user_id == current_user.id,
            FederatedClient.is_active == True
        ).count()
        
        online_clients = db.query(FederatedClient).filter(
            FederatedClient.user_id == current_user.id,
            FederatedClient.is_online == True
        ).count()
        
        # Get model stats
        total_models = db.query(FederatedModel).count()
        deployed_models = db.query(FederatedModel).filter(
            FederatedModel.is_deployed == True
        ).count()
        
        # Get training stats
        total_rounds = db.query(FederatedTrainingRound).count()
        completed_rounds = db.query(FederatedTrainingRound).filter(
            FederatedTrainingRound.status == "completed"
        ).count()
        
        return {
            "clients": {
                "total": total_clients,
                "active": active_clients,
                "online": online_clients
            },
            "models": {
                "total": total_models,
                "deployed": deployed_models
            },
            "training": {
                "total_rounds": total_rounds,
                "completed_rounds": completed_rounds,
                "success_rate": completed_rounds / total_rounds if total_rounds > 0 else 0
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get federated stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve federated statistics"
        )

