# app/mcp_config.py
# Scaffolds configuration parameters for local MCP servers (stdio).
# This configuration establishes local data gateways and remote extension connections.

import os
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

def get_github_mcp_config() -> StdioConnectionParams:
    """Returns StdioConnectionParams for the GitHub MCP server.
    
    This establishes a stdio transport channel to a Node.js-based subprocess.
    Security: It loads credentials dynamically from GITHUB_TOKEN or GITHUB_PERSONAL_ACCESS_TOKEN
    avoiding any hardcoded secrets in configurations.
    """
    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN")
    
    # Subprocess environment variables (for authentication context)
    env = os.environ.copy()
    if github_token:
        env["GITHUB_TOKEN"] = github_token
        env["GITHUB_PERSONAL_ACCESS_TOKEN"] = github_token
        
    command = os.environ.get("GITHUB_MCP_COMMAND", "npx")
    args_str = os.environ.get("GITHUB_MCP_ARGS")
    if args_str:
        args = args_str.split(",")
    else:
        # Default npx invocation arguments for the GitHub MCP server
        args = ["-y", "@modelcontextprotocol/server-github"]
        
    return StdioConnectionParams(
        server_params=StdioServerParameters(
            command=command,
            args=args,
            env=env
        )
    )

def get_spanner_graph_mcp_config() -> StdioConnectionParams:
    """Returns StdioConnectionParams for the Spanner Graph MCP server.
    
    This connects to the local Data Gateway to fetch Spanner Graph database schema/GQL.
    Security: Env values (SPANNER_INSTANCE, SPANNER_DATABASE, etc.) are read at runtime.
    """
    spanner_instance = os.environ.get("SPANNER_INSTANCE")
    spanner_database = os.environ.get("SPANNER_DATABASE")
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    
    # Subprocess environment variables (for configuration and credentials)
    env = os.environ.copy()
    if spanner_instance:
        env["SPANNER_INSTANCE"] = spanner_instance
    if spanner_database:
        env["SPANNER_DATABASE"] = spanner_database
    if project_id:
        env["GOOGLE_CLOUD_PROJECT"] = project_id
        
    command = os.environ.get("SPANNER_MCP_COMMAND", "npx")
    args_str = os.environ.get("SPANNER_MCP_ARGS")
    if args_str:
        args = args_str.split(",")
    else:
        # Default npx invocation arguments for the Spanner GCP MCP server
        args = ["-y", "@krzko/google-cloud-mcp", "spanner"]
        
    return StdioConnectionParams(
        server_params=StdioServerParameters(
            command=command,
            args=args,
            env=env
        )
    )
