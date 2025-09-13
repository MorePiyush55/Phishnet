"""Orchestrator utilities and helper functions."""

import asyncio
from typing import Dict, Any, List
from datetime import datetime

from app.core.orchestrator import PhishNetOrchestrator, get_orchestrator, OrchestrationResult
from src.common.constants import OperationType, OperationStatus, ThreatLevel


class OrchestratorUtils:
    """Utility functions for the orchestrator."""
    
    @staticmethod
    async def process_email_comprehensive(email_id: int) -> Dict[str, Any]:
        """
        Comprehensive email processing using the canonical orchestrator.
        
        This replaces the functionality from app.services.orchestrator.EnhancedEmailOrchestrator.
        """
        orchestrator = get_orchestrator()
        
        # Create email data payload
        email_data = {
            "email_id": email_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Process through the canonical orchestrator pipeline
        result = await orchestrator.orchestrate_email_processing(email_data)
        
        return {
            "success": result.success,
            "operation_id": result.operation_id,
            "result": result.result,
            "error": result.error,
            "timestamp": result.timestamp.isoformat()
        }
    
    @staticmethod
    async def get_analysis_summary(operation_id: str) -> Dict[str, Any]:
        """Get analysis summary for an operation."""
        orchestrator = get_orchestrator()
        operation = orchestrator.get_operation_status(operation_id)
        
        if not operation:
            return {"error": "Operation not found"}
        
        return {
            "operation_id": operation.id,
            "type": operation.type.value,
            "status": operation.status.value,
            "created_at": operation.created_at.isoformat(),
            "completed_at": operation.completed_at.isoformat() if operation.completed_at else None,
            "result": operation.result,
            "error": operation.error
        }
    
    @staticmethod
    def create_email_orchestrator_instance():
        """
        Create an email orchestrator instance.
        
        This provides compatibility for code expecting an orchestrator instance.
        """
        return EmailOrchestratorAdapter()


class EmailOrchestratorAdapter:
    """
    Adapter class to provide compatibility with the old orchestrator interface.
    
    This allows existing code to work with the canonical orchestrator
    without major refactoring.
    """
    
    def __init__(self):
        self._orchestrator = get_orchestrator()
    
    async def start(self):
        """Start the orchestrator."""
        await self._orchestrator.start()
    
    async def stop(self):
        """Stop the orchestrator."""
        await self._orchestrator.stop()
    
    async def process_email(self, email_id: int):
        """Process an email using the canonical orchestrator."""
        email_data = {
            "email_id": email_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        return await self._orchestrator.orchestrate_email_processing(email_data)
    
    async def process_email_comprehensive(self, email_id: int):
        """Comprehensive email processing."""
        return await OrchestratorUtils.process_email_comprehensive(email_id)


# Create singleton instances for backward compatibility
email_orchestrator = EmailOrchestratorAdapter()


class AnalysisOrchestrator:
    """Analysis orchestrator for backward compatibility."""
    
    def __init__(self):
        self._orchestrator = get_orchestrator()
    
    async def analyze_email_with_links(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email with links using canonical orchestrator."""
        return await self._orchestrator.orchestrate_email_processing(email_data)
    
    async def full_analysis_pipeline(self, email_id: int) -> Dict[str, Any]:
        """Full analysis pipeline."""
        email_data = {
            "email_id": email_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        result = await self._orchestrator.orchestrate_email_processing(email_data)
        
        return {
            "email_id": email_id,
            "analysis_complete": result.success,
            "threat_level": "unknown",  # Will be determined by the orchestrator
            "confidence": 0.0,
            "details": result.result
        }


# Compatibility functions for the old interface
async def process_email_comprehensive(email_id: int):
    """Process email comprehensively - compatibility function."""
    return await OrchestratorUtils.process_email_comprehensive(email_id)
