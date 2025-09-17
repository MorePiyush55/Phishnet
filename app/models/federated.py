"""Compatibility shim: expose federated models at app.models.federated

Re-exports federated-related models from app.models.security where they live.
"""

from app.models.security.federated import FederatedModel, FederatedClient, FederatedTrainingRound

__all__ = ["FederatedModel", "FederatedClient", "FederatedTrainingRound"]
