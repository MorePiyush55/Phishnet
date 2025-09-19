"""Database package initialization - MongoDB Only."""

from .mongodb import MongoDBManager

__all__ = [
    "MongoDBManager"
]
