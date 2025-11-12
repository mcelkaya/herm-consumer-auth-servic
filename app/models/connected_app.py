from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from app.db.session import Base
from app.core.config import settings


class ConnectedApp(Base):
    """Connected app model for email provider integrations"""
    
    __tablename__ = "connected_apps"
    __table_args__ = {"schema": settings.DATABASE_SCHEMA}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey(f"{settings.DATABASE_SCHEMA}.users.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False)  # gmail, outlook, yahoo
    provider_email = Column(String(255), nullable=False)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=True)
    token_expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationship with user
    user = relationship("User", back_populates="connected_apps")
    
    def __repr__(self):
        return f"<ConnectedApp {self.provider}:{self.provider_email}>"
