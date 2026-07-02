import os

class Config:
    """System-wide configuration settings."""
    # gemini-3.1-flash-lite: fast, cost-efficient model for all pipeline agents.
    # Free-tier quota for gemini-3.1-pro-preview is zero; route everything to flash-lite
    # until a paid quota is provisioned. Override via DEFAULT_MODEL / PRO_MODEL env-vars.
    DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "gemini-3.1-flash-lite")
    PRO_MODEL = os.environ.get("PRO_MODEL", "gemini-3.1-flash-lite")
