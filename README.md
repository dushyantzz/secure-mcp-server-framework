# Secure MCP Server (FastMCP)

A secure, context-optimized MCP server built with FastMCP, designed for FastMCP Cloud deployment. It includes authentication, rate limiting, input sanitization, sandboxed tool execution, dynamic context, monitoring, and multi-tenant scaffolding.

## Features
- FastMCP-compliant MCP server ready for Cloud
- JWT-like auth scaffold via AuthManager, API key support
- Role-based permission checks and audit logging
- Rate limiting and input sanitization
- Sandboxed tool execution with timeouts
- Built-in tools: echo, calculator, text_processor, secure_hash, uuid_generator, datetime_info, system_info (admin), context_summary
- Context manager with token budgets and eviction
- Metrics collector + basic anomaly hooks

## Quick start
1. Clone and setup
```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# set SECRET_KEY and ADMIN_PASSWORD in .env
```

2. Run locally
```
python -m secure_mcp_server.main
```

3. Use with MCP client
- Connect using stdio per FastMCP. Tools are auto-registered by decorators.

## FastMCP Cloud deployment
- This repo includes `fastmcp.yaml` manifest.
- Configure environment variables (SECRET_KEY, ADMIN_PASSWORD at minimum).
- Set start command from manifest (python -m secure_mcp_server.main).

## Configuration
See `.env.example` for all settings. Key vars: SECRET_KEY, ADMIN_PASSWORD, DATABASE_URL, ENABLE_TOOL_SANDBOXING.

## Extending tools
Add new tool functions in `secure_mcp_server/main.py` using `@mcp.tool()` and implement execution in `secure_mcp_server/tools.py` if centralized handling is preferred.

## Security notes
- Calculator uses safe eval with restricted namespace.
- Hash tool supports md5/sha1/sha256/sha512; prefer sha256+.
- System info tool is admin only.

## License
MIT
