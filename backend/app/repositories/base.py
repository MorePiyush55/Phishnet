"""
Base repository classes for the async repository pattern.
Provides common CRUD operations and query patterns.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar, Union
from uuid import UUID

from sqlalchemy import select, update, delete, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, joinedload
from sqlalchemy.sql import Select

from app.models.async_models import AsyncBase

# Generic type for model classes
ModelType = TypeVar("ModelType", bound=AsyncBase)
CreateSchemaType = TypeVar("CreateSchemaType")
UpdateSchemaType = TypeVar("UpdateSchemaType")


class BaseRepository(Generic[ModelType], ABC):
    """Base repository class with common async CRUD operations."""
    
    def __init__(self, session: AsyncSession, model: Type[ModelType]):
        self.session = session
        self.model = model
    
    async def create(self, **kwargs) -> ModelType:
        """Create a new model instance."""
        instance = self.model(**kwargs)
        self.session.add(instance)
        await self.session.commit()
        await self.session.refresh(instance)
        return instance
    
    async def get_by_id(self, id: UUID, load_relationships: bool = False) -> Optional[ModelType]:
        """Get model by ID with optional relationship loading."""
        query = select(self.model).where(self.model.id == id)
        
        if load_relationships:
            query = self._add_relationship_loads(query)
        
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def get_by_field(self, field_name: str, value: Any, load_relationships: bool = False) -> Optional[ModelType]:
        """Get model by field value."""
        field = getattr(self.model, field_name)
        query = select(self.model).where(field == value)
        
        if load_relationships:
            query = self._add_relationship_loads(query)
        
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def get_multi(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = None,
        load_relationships: bool = False
    ) -> List[ModelType]:
        """Get multiple models with pagination and filtering."""
        query = select(self.model)
        
        # Apply filters
        if filters:
            for field_name, value in filters.items():
                if hasattr(self.model, field_name):
                    field = getattr(self.model, field_name)
                    if isinstance(value, list):
                        query = query.where(field.in_(value))
                    elif isinstance(value, dict) and 'operator' in value:
                        # Support for complex filters like {'operator': 'gte', 'value': 100}
                        op = value['operator']
                        val = value['value']
                        if op == 'gte':
                            query = query.where(field >= val)
                        elif op == 'lte':
                            query = query.where(field <= val)
                        elif op == 'like':
                            query = query.where(field.like(f"%{val}%"))
                        elif op == 'ilike':
                            query = query.where(field.ilike(f"%{val}%"))
                    else:
                        query = query.where(field == value)
        
        # Apply ordering
        if order_by:
            if order_by.startswith('-'):
                field_name = order_by[1:]
                if hasattr(self.model, field_name):
                    field = getattr(self.model, field_name)
                    query = query.order_by(field.desc())
            else:
                if hasattr(self.model, order_by):
                    field = getattr(self.model, order_by)
                    query = query.order_by(field.asc())
        else:
            # Default ordering by created_at if available
            if hasattr(self.model, 'created_at'):
                query = query.order_by(self.model.created_at.desc())
        
        if load_relationships:
            query = self._add_relationship_loads(query)
        
        # Apply pagination
        query = query.offset(skip).limit(limit)
        
        result = await self.session.execute(query)
        return result.scalars().all()
    
    async def update(self, id: UUID, **kwargs) -> Optional[ModelType]:
        """Update model by ID."""
        # Remove None values to avoid overwriting with null
        update_data = {k: v for k, v in kwargs.items() if v is not None}
        
        if not update_data:
            return await self.get_by_id(id)
        
        # Update with updated_at if model has timestamp mixin
        if hasattr(self.model, 'updated_at'):
            from datetime import datetime, timezone
            update_data['updated_at'] = datetime.now(timezone.utc)
        
        query = (
            update(self.model)
            .where(self.model.id == id)
            .values(**update_data)
            .returning(self.model)
        )
        
        result = await self.session.execute(query)
        await self.session.commit()
        return result.scalar_one_or_none()
    
    async def delete(self, id: UUID) -> bool:
        """Delete model by ID."""
        query = delete(self.model).where(self.model.id == id)
        result = await self.session.execute(query)
        await self.session.commit()
        return result.rowcount > 0
    
    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count models with optional filtering."""
        query = select(func.count(self.model.id))
        
        if filters:
            for field_name, value in filters.items():
                if hasattr(self.model, field_name):
                    field = getattr(self.model, field_name)
                    if isinstance(value, list):
                        query = query.where(field.in_(value))
                    else:
                        query = query.where(field == value)
        
        result = await self.session.execute(query)
        return result.scalar()
    
    async def exists(self, **kwargs) -> bool:
        """Check if model exists with given conditions."""
        query = select(self.model.id)
        
        for field_name, value in kwargs.items():
            if hasattr(self.model, field_name):
                field = getattr(self.model, field_name)
                query = query.where(field == value)
        
        query = query.limit(1)
        result = await self.session.execute(query)
        return result.scalar() is not None
    
    def _add_relationship_loads(self, query: Select) -> Select:
        """Override in subclasses to add relationship loading."""
        return query
    
    async def bulk_create(self, objects: List[Dict[str, Any]]) -> List[ModelType]:
        """Bulk create multiple objects."""
        instances = [self.model(**obj) for obj in objects]
        self.session.add_all(instances)
        await self.session.commit()
        return instances
    
    async def bulk_update(self, updates: List[Dict[str, Any]]) -> int:
        """Bulk update multiple objects."""
        if not updates:
            return 0
        
        # Add updated_at timestamp if model supports it
        if hasattr(self.model, 'updated_at'):
            from datetime import datetime, timezone
            for update_data in updates:
                update_data['updated_at'] = datetime.now(timezone.utc)
        
        await self.session.execute(update(self.model), updates)
        await self.session.commit()
        return len(updates)


class PaginatedResult(Generic[ModelType]):
    """Paginated result wrapper."""
    
    def __init__(
        self, 
        items: List[ModelType], 
        total: int, 
        page: int, 
        per_page: int
    ):
        self.items = items
        self.total = total
        self.page = page
        self.per_page = per_page
        self.pages = (total + per_page - 1) // per_page
        self.has_prev = page > 1
        self.has_next = page < self.pages
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            'items': [item.dict() if hasattr(item, 'dict') else item for item in self.items],
            'pagination': {
                'page': self.page,
                'per_page': self.per_page,
                'total': self.total,
                'pages': self.pages,
                'has_prev': self.has_prev,
                'has_next': self.has_next
            }
        }


class BaseAsyncRepository(BaseRepository[ModelType]):
    """Enhanced base repository with pagination and search capabilities."""
    
    async def paginate(
        self,
        page: int = 1,
        per_page: int = 20,
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = None,
        load_relationships: bool = False
    ) -> PaginatedResult[ModelType]:
        """Get paginated results."""
        # Calculate offset
        skip = (page - 1) * per_page
        
        # Get total count
        total = await self.count(filters)
        
        # Get items
        items = await self.get_multi(
            skip=skip,
            limit=per_page,
            filters=filters,
            order_by=order_by,
            load_relationships=load_relationships
        )
        
        return PaginatedResult(
            items=items,
            total=total,
            page=page,
            per_page=per_page
        )
    
    async def search(
        self,
        query_text: str,
        search_fields: List[str],
        page: int = 1,
        per_page: int = 20,
        filters: Optional[Dict[str, Any]] = None
    ) -> PaginatedResult[ModelType]:
        """Full-text search across specified fields."""
        base_query = select(self.model)
        
        # Build search conditions
        search_conditions = []
        for field_name in search_fields:
            if hasattr(self.model, field_name):
                field = getattr(self.model, field_name)
                search_conditions.append(field.ilike(f"%{query_text}%"))
        
        if search_conditions:
            base_query = base_query.where(or_(*search_conditions))
        
        # Apply additional filters
        if filters:
            for field_name, value in filters.items():
                if hasattr(self.model, field_name):
                    field = getattr(self.model, field_name)
                    base_query = base_query.where(field == value)
        
        # Count total results
        count_query = select(func.count()).select_from(base_query.subquery())
        total_result = await self.session.execute(count_query)
        total = total_result.scalar()
        
        # Get paginated results
        skip = (page - 1) * per_page
        items_query = base_query.offset(skip).limit(per_page)
        
        # Default ordering by relevance (created_at desc)
        if hasattr(self.model, 'created_at'):
            items_query = items_query.order_by(self.model.created_at.desc())
        
        items_result = await self.session.execute(items_query)
        items = items_result.scalars().all()
        
        return PaginatedResult(
            items=items,
            total=total,
            page=page,
            per_page=per_page
        )
