"""Configuration management for the Secure MCP Server."""

import os
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Server Configuration
    server_name: str = Field(default="Secure MCP Server", description="Server name")
    debug: bool = Field(default=False, env="DEBUG")
    environment: str = Field(default="production", env="ENVIRONMENT")
    
    # Security Settings
    secret_key: str = Field(env="SECRET_KEY", description="Secret key for JWT tokens")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    
    # Database Configuration
    database_url: str = Field(
        default="sqlite+aiosqlite:///./secure_mcp.db", 
        env="DATABASE_URL",
        description="Database connection URL"
    )
    
    # Redis Configuration (optional)
    redis_url: Optional[str] = Field(default=None, env="REDIS_URL")
    
    # Context Management
    max_context_length: int = Field(default=8192, env="MAX_CONTEXT_LENGTH")
    max_tools_per_session: int = Field(default=50, env="MAX_TOOLS_PER_SESSION")
    session_timeout_minutes: int = Field(default=60, env="SESSION_TIMEOUT_MINUTES")
    
    # Multi-tenant Support
    enable_multi_tenant: bool = Field(default=True, env="ENABLE_MULTI_TENANT")
    default_tenant: str = Field(default="default", env="DEFAULT_TENANT")
    
    # Rate Limiting
    rate_limit_requests_per_minute: int = Field(default=60, env="RATE_LIMIT_RPM")
    rate_limit_tools_per_hour: int = Field(default=1000, env="RATE_LIMIT_TPH")
    
    # Monitoring and Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    metrics_retention_days: int = Field(default=30, env="METRICS_RETENTION_DAYS")
    
    # Security Features
    enable_audit_logging: bool = Field(default=True, env="ENABLE_AUDIT_LOGGING")
    enable_input_sanitization: bool = Field(default=True, env="ENABLE_INPUT_SANITIZATION")
    enable_rate_limiting: bool = Field(default=True, env="ENABLE_RATE_LIMITING")
    
    # Tool Execution
    tool_execution_timeout: int = Field(default=30, env="TOOL_EXECUTION_TIMEOUT")
    enable_tool_sandboxing: bool = Field(default=True, env="ENABLE_TOOL_SANDBOXING")
    
    # Admin Settings
    admin_username: str = Field(default="admin", env="ADMIN_USERNAME")
    admin_password: str = Field(default="admin123", env="ADMIN_PASSWORD")
    admin_email: str = Field(default="admin@example.com", env="ADMIN_EMAIL")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get application settings (singleton pattern)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Reload settings (useful for testing)."""
    global _settings
    _settings = None
    return get_settings()