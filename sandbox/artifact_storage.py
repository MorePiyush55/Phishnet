"""
Sandbox Artifact Storage System

Handles secure storage of sandbox analysis artifacts including screenshots,
DOM snapshots, network logs, and console output with configurable retention policies.
"""

import asyncio
import json
import logging
import os
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, BinaryIO
from urllib.parse import urlparse
import uuid

import structlog
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Optional imports for Google Cloud Storage. During test collection the
# google-cloud-storage package may not be installed in the environment; in
# that case, fall back to a local/no-op behavior to allow imports to succeed.
try:
    from google.cloud import storage as gcs
    from google.cloud.exceptions import NotFound, Forbidden
except Exception:
    gcs = None

    class NotFound(Exception):
        pass

    class Forbidden(Exception):
        pass
from PIL import Image
import zipfile
import hashlib

logger = structlog.get_logger(__name__)


class StorageError(Exception):
    """Raised when storage operations fail."""
    pass


class ArtifactType:
    """Artifact type constants."""
    SCREENSHOT = "screenshot"
    DOM_SNAPSHOT = "dom_snapshot"
    NETWORK_LOGS = "network_logs"
    CONSOLE_LOGS = "console_logs"
    ANALYSIS_REPORT = "analysis_report"
    ARCHIVE = "archive"


class ArtifactMetadata:
    """Metadata for stored artifacts."""
    
    def __init__(self, 
                 artifact_id: str,
                 job_id: str,
                 artifact_type: str,
                 file_path: str,
                 content_type: str,
                 size_bytes: int,
                 checksum: str,
                 created_at: datetime = None,
                 expires_at: datetime = None,
                 metadata: Dict[str, Any] = None):
        self.artifact_id = artifact_id
        self.job_id = job_id
        self.artifact_type = artifact_type
        self.file_path = file_path
        self.content_type = content_type
        self.size_bytes = size_bytes
        self.checksum = checksum
        self.created_at = created_at or datetime.utcnow()
        self.expires_at = expires_at
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "job_id": self.job_id,
            "artifact_type": self.artifact_type,
            "file_path": self.file_path,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "checksum": self.checksum,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ArtifactMetadata':
        """Create from dictionary."""
        data = data.copy()
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        if data.get('expires_at'):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        return cls(**data)


class BaseArtifactStorage:
    """Base class for artifact storage backends."""
    
    def __init__(self, bucket_name: str, retention_days: int = 7):
        self.bucket_name = bucket_name
        self.retention_days = retention_days
        self.default_expires_at = datetime.utcnow() + timedelta(days=retention_days)
    
    async def store_artifact(self,
                           job_id: str,
                           artifact_type: str,
                           file_path: Union[str, Path],
                           content_type: str = None,
                           metadata: Dict[str, Any] = None) -> ArtifactMetadata:
        """Store an artifact file."""
        raise NotImplementedError
    
    async def store_data(self,
                        job_id: str,
                        artifact_type: str,
                        data: Union[str, bytes],
                        filename: str,
                        content_type: str = None,
                        metadata: Dict[str, Any] = None) -> ArtifactMetadata:
        """Store artifact data directly."""
        raise NotImplementedError
    
    async def retrieve_artifact(self, artifact_id: str) -> Optional[bytes]:
        """Retrieve artifact data by ID."""
        raise NotImplementedError
    
    async def get_artifact_url(self, artifact_id: str, expires_in: int = 3600) -> Optional[str]:
        """Get signed URL for artifact access."""
        raise NotImplementedError
    
    async def delete_artifact(self, artifact_id: str) -> bool:
        """Delete an artifact."""
        raise NotImplementedError
    
    async def cleanup_expired_artifacts(self) -> int:
        """Clean up expired artifacts."""
        raise NotImplementedError
    
    def _calculate_checksum(self, data: bytes) -> str:
        """Calculate SHA-256 checksum."""
        return hashlib.sha256(data).hexdigest()
    
    def _generate_storage_path(self, job_id: str, artifact_type: str, filename: str) -> str:
        """Generate storage path for artifact."""
        date_prefix = datetime.utcnow().strftime("%Y/%m/%d")
        return f"artifacts/{date_prefix}/{job_id}/{artifact_type}/{filename}"


class S3ArtifactStorage(BaseArtifactStorage):
    """Amazon S3 artifact storage backend."""
    
    def __init__(self, bucket_name: str, retention_days: int = 7, region: str = "us-east-1"):
        super().__init__(bucket_name, retention_days)
        self.region = region
        self.s3_client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize S3 client."""
        try:
            self.s3_client = boto3.client(
                's3',
                region_name=self.region,
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
            )
            
            # Test connection
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            logger.info("S3 storage initialized", bucket=self.bucket_name, region=self.region)
            
        except NoCredentialsError:
            logger.error("AWS credentials not found")
            raise StorageError("AWS credentials not configured")
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                logger.error("S3 bucket not found", bucket=self.bucket_name)
                raise StorageError(f"S3 bucket not found: {self.bucket_name}")
            else:
                logger.error("S3 initialization failed", error=str(e))
                raise StorageError(f"S3 initialization failed: {e}")
    
    async def store_artifact(self,
                           job_id: str,
                           artifact_type: str,
                           file_path: Union[str, Path],
                           content_type: str = None,
                           metadata: Dict[str, Any] = None) -> ArtifactMetadata:
        """Store artifact file in S3."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise StorageError(f"File not found: {file_path}")
        
        # Read file data
        with open(file_path, 'rb') as f:
            data = f.read()
        
        return await self.store_data(
            job_id=job_id,
            artifact_type=artifact_type,
            data=data,
            filename=file_path.name,
            content_type=content_type,
            metadata=metadata
        )
    
    async def store_data(self,
                        job_id: str,
                        artifact_type: str,
                        data: Union[str, bytes],
                        filename: str,
                        content_type: str = None,
                        metadata: Dict[str, Any] = None) -> ArtifactMetadata:
        """Store artifact data in S3."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        artifact_id = str(uuid.uuid4())
        storage_path = self._generate_storage_path(job_id, artifact_type, filename)
        
        # Prepare metadata
        s3_metadata = {
            'artifact-id': artifact_id,
            'job-id': job_id,
            'artifact-type': artifact_type,
            'created-at': datetime.utcnow().isoformat(),
            'expires-at': self.default_expires_at.isoformat()
        }
        
        if metadata:
            for key, value in metadata.items():
                s3_metadata[f'custom-{key}'] = str(value)
        
        # Determine content type
        if not content_type:
            if filename.endswith('.png'):
                content_type = 'image/png'
            elif filename.endswith('.html'):
                content_type = 'text/html'
            elif filename.endswith('.json'):
                content_type = 'application/json'
            else:
                content_type = 'application/octet-stream'
        
        try:
            # Upload to S3 with lifecycle policy
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=storage_path,
                Body=data,
                ContentType=content_type,
                Metadata=s3_metadata,
                StorageClass='STANDARD_IA',  # Cost-effective for short-term storage
                Expires=self.default_expires_at
            )
            
            # Create artifact metadata
            artifact_metadata = ArtifactMetadata(
                artifact_id=artifact_id,
                job_id=job_id,
                artifact_type=artifact_type,
                file_path=storage_path,
                content_type=content_type,
                size_bytes=len(data),
                checksum=self._calculate_checksum(data),
                expires_at=self.default_expires_at,
                metadata=metadata
            )
            
            logger.info("Artifact stored in S3", 
                       artifact_id=artifact_id, 
                       job_id=job_id, 
                       type=artifact_type,
                       size=len(data))
            
            return artifact_metadata
            
        except ClientError as e:
            logger.error("Failed to store artifact in S3", error=str(e))
            raise StorageError(f"S3 upload failed: {e}")
    
    async def retrieve_artifact(self, artifact_id: str) -> Optional[bytes]:
        """Retrieve artifact data from S3."""
        try:
            # Find artifact by metadata
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix="artifacts/"
            )
            
            for obj in response.get('Contents', []):
                try:
                    head_response = self.s3_client.head_object(
                        Bucket=self.bucket_name,
                        Key=obj['Key']
                    )
                    
                    if head_response['Metadata'].get('artifact-id') == artifact_id:
                        # Found the artifact
                        get_response = self.s3_client.get_object(
                            Bucket=self.bucket_name,
                            Key=obj['Key']
                        )
                        return get_response['Body'].read()
                        
                except ClientError:
                    continue
            
            return None
            
        except ClientError as e:
            logger.error("Failed to retrieve artifact from S3", artifact_id=artifact_id, error=str(e))
            return None
    
    async def get_artifact_url(self, artifact_id: str, expires_in: int = 3600) -> Optional[str]:
        """Get signed URL for S3 artifact."""
        try:
            # Find artifact path
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix="artifacts/"
            )
            
            for obj in response.get('Contents', []):
                try:
                    head_response = self.s3_client.head_object(
                        Bucket=self.bucket_name,
                        Key=obj['Key']
                    )
                    
                    if head_response['Metadata'].get('artifact-id') == artifact_id:
                        # Generate signed URL
                        url = self.s3_client.generate_presigned_url(
                            'get_object',
                            Params={'Bucket': self.bucket_name, 'Key': obj['Key']},
                            ExpiresIn=expires_in
                        )
                        return url
                        
                except ClientError:
                    continue
            
            return None
            
        except ClientError as e:
            logger.error("Failed to generate S3 URL", artifact_id=artifact_id, error=str(e))
            return None
    
    async def delete_artifact(self, artifact_id: str) -> bool:
        """Delete artifact from S3."""
        try:
            # Find and delete artifact
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix="artifacts/"
            )
            
            for obj in response.get('Contents', []):
                try:
                    head_response = self.s3_client.head_object(
                        Bucket=self.bucket_name,
                        Key=obj['Key']
                    )
                    
                    if head_response['Metadata'].get('artifact-id') == artifact_id:
                        self.s3_client.delete_object(
                            Bucket=self.bucket_name,
                            Key=obj['Key']
                        )
                        logger.info("Artifact deleted from S3", artifact_id=artifact_id)
                        return True
                        
                except ClientError:
                    continue
            
            return False
            
        except ClientError as e:
            logger.error("Failed to delete artifact from S3", artifact_id=artifact_id, error=str(e))
            return False
    
    async def cleanup_expired_artifacts(self) -> int:
        """Clean up expired artifacts from S3."""
        try:
            deleted_count = 0
            current_time = datetime.utcnow()
            
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix="artifacts/"
            )
            
            for obj in response.get('Contents', []):
                try:
                    head_response = self.s3_client.head_object(
                        Bucket=self.bucket_name,
                        Key=obj['Key']
                    )
                    
                    expires_at_str = head_response['Metadata'].get('expires-at')
                    if expires_at_str:
                        expires_at = datetime.fromisoformat(expires_at_str)
                        if current_time > expires_at:
                            self.s3_client.delete_object(
                                Bucket=self.bucket_name,
                                Key=obj['Key']
                            )
                            deleted_count += 1
                            
                except ClientError:
                    continue
            
            logger.info("S3 cleanup completed", deleted_count=deleted_count)
            return deleted_count
            
        except ClientError as e:
            logger.error("S3 cleanup failed", error=str(e))
            return 0


class GCSArtifactStorage(BaseArtifactStorage):
    """Google Cloud Storage artifact storage backend."""
    
    def __init__(self, bucket_name: str, retention_days: int = 7):
        super().__init__(bucket_name, retention_days)
        self.gcs_client = None
        self.bucket = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize GCS client."""
        try:
            self.gcs_client = gcs.Client()
            self.bucket = self.gcs_client.bucket(self.bucket_name)
            
            # Test bucket access
            if not self.bucket.exists():
                raise StorageError(f"GCS bucket not found: {self.bucket_name}")
            
            logger.info("GCS storage initialized", bucket=self.bucket_name)
            
        except Exception as e:
            logger.error("GCS initialization failed", error=str(e))
            raise StorageError(f"GCS initialization failed: {e}")
    
    async def store_artifact(self,
                           job_id: str,
                           artifact_type: str,
                           file_path: Union[str, Path],
                           content_type: str = None,
                           metadata: Dict[str, Any] = None) -> ArtifactMetadata:
        """Store artifact file in GCS."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise StorageError(f"File not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        return await self.store_data(
            job_id=job_id,
            artifact_type=artifact_type,
            data=data,
            filename=file_path.name,
            content_type=content_type,
            metadata=metadata
        )
    
    async def store_data(self,
                        job_id: str,
                        artifact_type: str,
                        data: Union[str, bytes],
                        filename: str,
                        content_type: str = None,
                        metadata: Dict[str, Any] = None) -> ArtifactMetadata:
        """Store artifact data in GCS."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        artifact_id = str(uuid.uuid4())
        storage_path = self._generate_storage_path(job_id, artifact_type, filename)
        
        # Determine content type
        if not content_type:
            if filename.endswith('.png'):
                content_type = 'image/png'
            elif filename.endswith('.html'):
                content_type = 'text/html'
            elif filename.endswith('.json'):
                content_type = 'application/json'
            else:
                content_type = 'application/octet-stream'
        
        try:
            # Create blob
            blob = self.bucket.blob(storage_path)
            
            # Set metadata
            blob.metadata = {
                'artifact_id': artifact_id,
                'job_id': job_id,
                'artifact_type': artifact_type,
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': self.default_expires_at.isoformat()
            }
            
            if metadata:
                blob.metadata.update(metadata)
            
            # Upload data
            blob.upload_from_string(data, content_type=content_type)
            
            # Set lifecycle policy for automatic deletion
            blob.custom_time = self.default_expires_at
            
            # Create artifact metadata
            artifact_metadata = ArtifactMetadata(
                artifact_id=artifact_id,
                job_id=job_id,
                artifact_type=artifact_type,
                file_path=storage_path,
                content_type=content_type,
                size_bytes=len(data),
                checksum=self._calculate_checksum(data),
                expires_at=self.default_expires_at,
                metadata=metadata
            )
            
            logger.info("Artifact stored in GCS", 
                       artifact_id=artifact_id, 
                       job_id=job_id, 
                       type=artifact_type,
                       size=len(data))
            
            return artifact_metadata
            
        except Exception as e:
            logger.error("Failed to store artifact in GCS", error=str(e))
            raise StorageError(f"GCS upload failed: {e}")
    
    async def retrieve_artifact(self, artifact_id: str) -> Optional[bytes]:
        """Retrieve artifact data from GCS."""
        try:
            # List and search for artifact
            for blob in self.bucket.list_blobs(prefix="artifacts/"):
                if blob.metadata and blob.metadata.get('artifact_id') == artifact_id:
                    return blob.download_as_bytes()
            
            return None
            
        except Exception as e:
            logger.error("Failed to retrieve artifact from GCS", artifact_id=artifact_id, error=str(e))
            return None
    
    async def get_artifact_url(self, artifact_id: str, expires_in: int = 3600) -> Optional[str]:
        """Get signed URL for GCS artifact."""
        try:
            # Find artifact blob
            for blob in self.bucket.list_blobs(prefix="artifacts/"):
                if blob.metadata and blob.metadata.get('artifact_id') == artifact_id:
                    # Generate signed URL
                    url = blob.generate_signed_url(
                        version="v4",
                        expiration=timedelta(seconds=expires_in),
                        method="GET"
                    )
                    return url
            
            return None
            
        except Exception as e:
            logger.error("Failed to generate GCS URL", artifact_id=artifact_id, error=str(e))
            return None
    
    async def delete_artifact(self, artifact_id: str) -> bool:
        """Delete artifact from GCS."""
        try:
            # Find and delete artifact
            for blob in self.bucket.list_blobs(prefix="artifacts/"):
                if blob.metadata and blob.metadata.get('artifact_id') == artifact_id:
                    blob.delete()
                    logger.info("Artifact deleted from GCS", artifact_id=artifact_id)
                    return True
            
            return False
            
        except Exception as e:
            logger.error("Failed to delete artifact from GCS", artifact_id=artifact_id, error=str(e))
            return False
    
    async def cleanup_expired_artifacts(self) -> int:
        """Clean up expired artifacts from GCS."""
        try:
            deleted_count = 0
            current_time = datetime.utcnow()
            
            for blob in self.bucket.list_blobs(prefix="artifacts/"):
                try:
                    if blob.metadata:
                        expires_at_str = blob.metadata.get('expires_at')
                        if expires_at_str:
                            expires_at = datetime.fromisoformat(expires_at_str)
                            if current_time > expires_at:
                                blob.delete()
                                deleted_count += 1
                                
                except Exception:
                    continue
            
            logger.info("GCS cleanup completed", deleted_count=deleted_count)
            return deleted_count
            
        except Exception as e:
            logger.error("GCS cleanup failed", error=str(e))
            return 0


class ArtifactManager:
    """High-level artifact management with automatic storage backend selection."""
    
    def __init__(self, bucket_name: str = None, retention_days: int = 7):
        """Initialize artifact manager."""
        self.bucket_name = bucket_name or os.getenv('ARTIFACTS_BUCKET', 'phishnet-sandbox-artifacts')
        self.retention_days = retention_days
        self.storage_backend = self._initialize_storage_backend()
    
    def _initialize_storage_backend(self) -> BaseArtifactStorage:
        """Initialize appropriate storage backend."""
        # Try S3 first
        if os.getenv('AWS_ACCESS_KEY_ID'):
            try:
                return S3ArtifactStorage(self.bucket_name, self.retention_days)
            except StorageError:
                logger.warning("S3 storage initialization failed, trying GCS")
        
        # Try GCS
        if os.getenv('GOOGLE_APPLICATION_CREDENTIALS'):
            try:
                return GCSArtifactStorage(self.bucket_name, self.retention_days)
            except StorageError:
                logger.warning("GCS storage initialization failed")
        
        raise StorageError("No valid storage backend found. Configure AWS or GCS credentials.")
    
    async def store_screenshot(self, job_id: str, file_path: Path, user_agent_type: str) -> ArtifactMetadata:
        """Store a screenshot artifact."""
        return await self.storage_backend.store_artifact(
            job_id=job_id,
            artifact_type=ArtifactType.SCREENSHOT,
            file_path=file_path,
            content_type='image/png',
            metadata={'user_agent_type': user_agent_type}
        )
    
    async def store_dom_snapshot(self, job_id: str, file_path: Path, user_agent_type: str) -> ArtifactMetadata:
        """Store a DOM snapshot artifact."""
        return await self.storage_backend.store_artifact(
            job_id=job_id,
            artifact_type=ArtifactType.DOM_SNAPSHOT,
            file_path=file_path,
            content_type='text/html',
            metadata={'user_agent_type': user_agent_type}
        )
    
    async def store_logs(self, job_id: str, logs_data: Dict[str, Any], log_type: str) -> ArtifactMetadata:
        """Store logs as JSON."""
        logs_json = json.dumps(logs_data, indent=2)
        return await self.storage_backend.store_data(
            job_id=job_id,
            artifact_type=log_type,
            data=logs_json,
            filename=f"{log_type}.json",
            content_type='application/json'
        )
    
    async def create_analysis_archive(self, job_id: str, artifacts: List[ArtifactMetadata]) -> ArtifactMetadata:
        """Create a ZIP archive of all job artifacts."""
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
            with zipfile.ZipFile(temp_file, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add analysis summary
                summary = {
                    'job_id': job_id,
                    'created_at': datetime.utcnow().isoformat(),
                    'artifacts': [artifact.to_dict() for artifact in artifacts]
                }
                zip_file.writestr('analysis_summary.json', json.dumps(summary, indent=2))
                
                # Add artifacts
                for artifact in artifacts:
                    try:
                        data = await self.storage_backend.retrieve_artifact(artifact.artifact_id)
                        if data:
                            zip_file.writestr(f"{artifact.artifact_type}/{artifact.artifact_id}", data)
                    except Exception as e:
                        logger.warning("Failed to add artifact to archive", 
                                     artifact_id=artifact.artifact_id, error=str(e))
            
            # Store archive
            return await self.storage_backend.store_artifact(
                job_id=job_id,
                artifact_type=ArtifactType.ARCHIVE,
                file_path=temp_file.name,
                content_type='application/zip'
            )
    
    async def get_artifact_url(self, artifact_id: str, expires_in: int = 3600) -> Optional[str]:
        """Get signed URL for artifact access."""
        return await self.storage_backend.get_artifact_url(artifact_id, expires_in)
    
    async def cleanup_expired_artifacts(self) -> int:
        """Clean up expired artifacts."""
        return await self.storage_backend.cleanup_expired_artifacts()


# Global artifact manager instance
_artifact_manager: Optional[ArtifactManager] = None


def get_artifact_manager() -> ArtifactManager:
    """Get or create global artifact manager."""
    global _artifact_manager
    
    if _artifact_manager is None:
        bucket_name = os.getenv('ARTIFACTS_BUCKET', 'phishnet-sandbox-artifacts')
        retention_days = int(os.getenv('ARTIFACTS_RETENTION_DAYS', '7'))
        _artifact_manager = ArtifactManager(bucket_name, retention_days)
    
    return _artifact_manager
