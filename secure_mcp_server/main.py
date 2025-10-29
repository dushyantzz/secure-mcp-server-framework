"""Main MCP server implementation using FastMCP."""

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP
from mcp.types import Resource, Tool
import structlog

from .config import Settings, get_settings
from .auth import AuthManager
from .tools import ToolRegistry
from .security import SecurityManager
from .monitoring import MetricsCollector
from .database import DatabaseManager
from .context import ContextManager

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


class SecureMCPServer:
    """Secure MCP Server with authentication and monitoring."""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.mcp = FastMCP(name="Secure MCP Server Framework")
        
        # Initialize components
        self.auth_manager = AuthManager(self.settings)
        self.security_manager = SecurityManager(self.settings)
        self.metrics_collector = MetricsCollector()
        self.database_manager = DatabaseManager(self.settings.database_url)
        self.context_manager = ContextManager(self.settings)
        self.tool_registry = ToolRegistry(
            auth_manager=self.auth_manager,
            security_manager=self.security_manager,
            metrics_collector=self.metrics_collector,
            context_manager=self.context_manager
        )
        
        # Setup MCP server
        self._setup_server()
    
    def _setup_server(self):
        """Setup MCP server with security middleware and tools."""
        
        # Add authentication middleware
        @self.mcp.middleware
        async def auth_middleware(request, call_next):
            """Authentication middleware for all MCP requests."""
            # Extract user context from request if available
            user_context = await self.auth_manager.get_user_context(request)
            
            # Add user context to request
            request.user_context = user_context
            
            # Log request
            logger.info(
                "MCP request received",
                method=getattr(request, 'method', 'unknown'),
                user_id=user_context.get('user_id') if user_context else None,
                tenant_id=user_context.get('tenant_id', 'default') if user_context else 'default'
            )
            
            # Record metrics
            self.metrics_collector.record_request()
            
            # Continue with request
            response = await call_next(request)
            
            return response
        
        # Add security middleware
        @self.mcp.middleware
        async def security_middleware(request, call_next):
            """Security middleware for input validation and rate limiting."""
            # Rate limiting
            client_id = getattr(request, 'client_id', 'anonymous')
            if not await self.security_manager.check_rate_limit(client_id):
                self.metrics_collector.record_rate_limit_hit()
                raise Exception("Rate limit exceeded")
            
            # Input sanitization
            if hasattr(request, 'params'):
                request.params = self.security_manager.sanitize_input(request.params)
            
            response = await call_next(request)
            return response
        
        # Register all tools
        self._register_tools()
        
        # Register resources
        self._register_resources()
        
        # Register prompts
        self._register_prompts()
    
    def _register_tools(self):
        """Register all available tools."""
        
        @self.mcp.tool()
        async def echo(text: str) -> Dict[str, Any]:
            """Echo back the provided text.
            
            Args:
                text: The text to echo back
                
            Returns:
                Dict containing the echoed text and metadata
            """
            return await self.tool_registry.execute_tool(
                'echo', 
                {'text': text}, 
                self.mcp.current_request
            )
        
        @self.mcp.tool()
        async def calculator(expression: str) -> Dict[str, Any]:
            """Perform mathematical calculations safely.
            
            Args:
                expression: Mathematical expression to evaluate (e.g., "2 + 2 * 3")
                
            Returns:
                Dict containing the calculation result
            """
            return await self.tool_registry.execute_tool(
                'calculator', 
                {'expression': expression}, 
                self.mcp.current_request
            )
        
        @self.mcp.tool()
        async def text_processor(text: str, operation: str) -> Dict[str, Any]:
            """Process text with various operations.
            
            Args:
                text: The text to process
                operation: Operation to perform (uppercase, lowercase, reverse, word_count, title_case)
                
            Returns:
                Dict containing the processed text
            """
            return await self.tool_registry.execute_tool(
                'text_processor', 
                {'text': text, 'operation': operation}, 
                self.mcp.current_request
            )
        
        @self.mcp.tool()
        async def secure_hash(text: str, algorithm: str = "sha256") -> Dict[str, Any]:
            """Generate secure hash of text.
            
            Args:
                text: Text to hash
                algorithm: Hashing algorithm (sha256, sha512, md5)
                
            Returns:
                Dict containing the hash value
            """
            return await self.tool_registry.execute_tool(
                'secure_hash', 
                {'text': text, 'algorithm': algorithm}, 
                self.mcp.current_request
            )
        
        @self.mcp.tool()
        async def uuid_generator(version: int = 4) -> Dict[str, Any]:
            """Generate UUID.
            
            Args:
                version: UUID version (1, 4)
                
            Returns:
                Dict containing the generated UUID
            """
            return await self.tool_registry.execute_tool(
                'uuid_generator', 
                {'version': version}, 
                self.mcp.current_request
            )
        
        @self.mcp.tool() 
        async def datetime_info(timezone: str = "UTC", format_type: str = "iso") -> Dict[str, Any]:
            """Get current date and time information.
            
            Args:
                timezone: Timezone (UTC, local)
                format_type: Format type (iso, readable, timestamp)
                
            Returns:
                Dict containing datetime information
            """
            return await self.tool_registry.execute_tool(
                'datetime_info', 
                {'timezone': timezone, 'format_type': format_type}, 
                self.mcp.current_request
            )
        
        @self.mcp.tool()
        async def system_info() -> Dict[str, Any]:
            """Get system information (requires admin privileges).
            
            Returns:
                Dict containing system information
            """
            return await self.tool_registry.execute_tool(
                'system_info', 
                {}, 
                self.mcp.current_request
            )
        
        @self.mcp.tool()
        async def context_summary(session_id: str) -> Dict[str, Any]:
            """Get context summary for a session.
            
            Args:
                session_id: Session ID to get context for
                
            Returns:
                Dict containing context summary
            """
            return await self.tool_registry.execute_tool(
                'context_summary', 
                {'session_id': session_id}, 
                self.mcp.current_request
            )
    
    def _register_resources(self):
        """Register MCP resources."""
        
        @self.mcp.resource("config://settings")
        async def get_server_config() -> str:
            """Get server configuration (admin only)."""
            # Check admin privileges
            user_context = getattr(self.mcp.current_request, 'user_context', {})
            if not user_context.get('is_admin', False):
                raise Exception("Admin privileges required")
            
            config = {
                "version": "1.0.0",
                "max_context_length": self.settings.max_context_length,
                "session_timeout_minutes": self.settings.session_timeout_minutes,
                "enable_multi_tenant": self.settings.enable_multi_tenant
            }
            
            return str(config)
        
        @self.mcp.resource("metrics://current")
        async def get_metrics() -> str:
            """Get current metrics (admin only)."""
            # Check admin privileges
            user_context = getattr(self.mcp.current_request, 'user_context', {})
            if not user_context.get('is_admin', False):
                raise Exception("Admin privileges required")
            
            metrics = await self.metrics_collector.get_current_metrics()
            return str(metrics)
    
    def _register_prompts(self):
        """Register MCP prompts."""
        
        @self.mcp.prompt("security-audit")
        async def security_audit_prompt(
            time_range: str = "24h", 
            severity: str = "all"
        ) -> List[Dict[str, Any]]:
            """Generate security audit prompt with recent security events.
            
            Args:
                time_range: Time range for audit (1h, 24h, 7d)
                severity: Severity filter (all, high, medium, low)
            """
            # Check admin privileges
            user_context = getattr(self.mcp.current_request, 'user_context', {})
            if not user_context.get('is_admin', False):
                raise Exception("Admin privileges required")
            
            events = await self.security_manager.get_audit_events(
                time_range=time_range,
                severity=severity
            )
            
            return [
                {
                    "role": "system",
                    "content": f"Security Audit Report for {time_range}\n\nAnalyze the following security events and provide recommendations:"
                },
                {
                    "role": "user", 
                    "content": f"Security Events:\n{events}"
                }
            ]
        
        @self.mcp.prompt("performance-analysis")
        async def performance_analysis_prompt(
            metric_type: str = "all"
        ) -> List[Dict[str, Any]]:
            """Generate performance analysis prompt with system metrics.
            
            Args:
                metric_type: Type of metrics to analyze (all, tools, sessions, system)
            """
            metrics = await self.metrics_collector.get_performance_metrics(
                metric_type=metric_type
            )
            
            return [
                {
                    "role": "system",
                    "content": "Analyze the following performance metrics and suggest optimizations:"
                },
                {
                    "role": "user",
                    "content": f"Performance Metrics:\n{metrics}"
                }
            ]
    
    async def initialize(self):
        """Initialize all server components."""
        logger.info("Initializing Secure MCP Server")
        
        # Initialize database
        await self.database_manager.initialize()
        
        # Initialize context manager
        await self.context_manager.initialize()
        
        # Initialize tool registry
        await self.tool_registry.initialize()
        
        logger.info("Secure MCP Server initialized successfully")
    
    async def cleanup(self):
        """Cleanup server components."""
        logger.info("Cleaning up Secure MCP Server")
        
        await self.context_manager.cleanup()
        await self.database_manager.cleanup()
        
        logger.info("Secure MCP Server cleanup complete")
    
    async def run(self):
        """Run the MCP server."""
        try:
            await self.initialize()
            await self.mcp.run()
        finally:
            await self.cleanup()


def main():
    """Main entry point for the secure MCP server."""
    import sys
    
    # Load settings
    settings = get_settings()
    
    # Create and run server
    server = SecureMCPServer(settings)
    
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
        sys.exit(0)
    except Exception as e:
        logger.error("Server error", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()