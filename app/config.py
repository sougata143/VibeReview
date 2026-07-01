import os

class Config:
    """System-wide configuration settings."""
    DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "gemini-3.1-flash-lite")
