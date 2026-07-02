import os

class Config:
    """System-wide configuration settings."""
    DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "gemini-3.1-flash-lite")
    PRO_MODEL = os.environ.get("PRO_MODEL", "gemini-3.1-pro")
