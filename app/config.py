import os

class Config:
    """System-wide configuration settings."""
    # gemini-3.1-flash-lite: fast, deterministic tasks (Search, Task-Breakdown, Coding agents)
    DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "gemini-3.1-flash-lite")
    # gemini-3.1-pro-preview: high-capacity reasoning tasks (Story, Impact agents)
    PRO_MODEL = os.environ.get("PRO_MODEL", "gemini-3.1-pro-preview")
