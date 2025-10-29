"""Configuration management for MCP Server."""

import os
from typing import Optional, List
from pydantic import BaseSettings, Field
from pydantic_settings import BaseSettings as PydanticBaseSettings


class Settings(PydanticBaseSettings):
    """Application settings."""
    
    # Server Configuration
    server_host: str = Field(default="0.0.0.0", env="SERVER_HOST")
    server_port: int = Field(default=8000, env="SERVER_PORT")
    debug: bool = Field(default=False, env="DEBUG")
    environment: str = Field(default="production", env="ENVIRONMENT")
    
    # Security
    secret_key: str = Field(env="SECRET_KEY")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    
    # Database
    database_url: str = Field(default="sqlite:///./mcp_server.db", env="DATABASE_URL")
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    
    # OAuth Configuration
    google_client_id: Optional[str] = Field(default=None, env="GOOGLE_CLIENT_ID")
    google_client_secret: Optional[str] = Field(default=None, env="GOOGLE_CLIENT_SECRET")
    github_client_id: Optional[str] = Field(default=None, env="GITHUB_CLIENT_ID")
    github_client_secret: Optional[str] = Field(default=None, env="GITHUB_CLIENT_SECRET")
    
    # Monitoring
    prometheus_port: int = Field(default=9090, env="PROMETHEUS_PORT")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    # Context Management
    max_context_length: int = Field(default=4096, env="MAX_CONTEXT_LENGTH")
    max_tools_per_session: int = Field(default=50, env="MAX_TOOLS_PER_SESSION")
    session_timeout_minutes: int = Field(default=60, env="SESSION_TIMEOUT_MINUTES")
    
    # Multi-tenant
    enable_multi_tenant: bool = Field(default=True, env="ENABLE_MULTI_TENANT")
    default_tenant: str = Field(default="default", env="DEFAULT_TENANT")
    
    # Allowed origins for CORS
    allowed_origins: List[str] = Field(default=["*"], env="ALLOWED_ORIGINS")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings."""
    return settings