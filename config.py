#!/usr/bin/env python3
"""
config.py - Centralized configuration for T-Pot Honeypot Analyzer

Configuration is loaded from environment variables or .env file.
Copy .env.example to .env and customize for your setup.
"""

import os
from pathlib import Path

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, rely on environment variables

# =============================================================================
# Elasticsearch Configuration (T-Pot Hive)
# =============================================================================
ES_HOST = os.getenv("ES_HOST", "localhost")
ES_PORT = int(os.getenv("ES_PORT", "64298"))
ES_INDEX_PATTERN = os.getenv("ES_INDEX_PATTERN", "logstash-*")
ES_USE_SSL = os.getenv("ES_USE_SSL", "false").lower() == "true"
ES_VERIFY_CERTS = os.getenv("ES_VERIFY_CERTS", "true").lower() == "true"
ES_USERNAME = os.getenv("ES_USERNAME", "")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")

# =============================================================================
# LLM Configuration (LM Studio or OpenAI-compatible API)
# =============================================================================
LLM_HOST = os.getenv("LLM_HOST", "localhost")
LLM_PORT = int(os.getenv("LLM_PORT", "1234"))
LLM_API_URL = os.getenv("LLM_API_URL", f"http://{LLM_HOST}:{LLM_PORT}/v1/chat/completions")
LLM_MODEL = os.getenv("LLM_MODEL", "")  # Empty = use default loaded model
LLM_API_KEY = os.getenv("LLM_API_KEY", "")  # Optional, for OpenAI/Anthropic

# =============================================================================
# Analysis Settings
# =============================================================================
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "120"))
DELAY_BETWEEN_REQUESTS = float(os.getenv("DELAY_BETWEEN_REQUESTS", "0.5"))
MAX_CONSECUTIVE_FAILURES = int(os.getenv("MAX_CONSECUTIVE_FAILURES", "3"))

# =============================================================================
# Honeypot Filtering
# =============================================================================
# Honeypot types to EXCLUDE (network analysis tools without meaningful shell input)
EXCLUDE_TYPES = os.getenv("EXCLUDE_TYPES", "Fatt,Suricata,P0f").split(",")

# Honeypot types known to have 'input' field (for reference)
INPUT_TYPES = ["Cowrie", "Adbhoney", "Dicompot"]

# =============================================================================
# Output Settings
# =============================================================================
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "output"))
CACHE_FILE = Path(os.getenv("CACHE_FILE", "analysis_cache.json"))


def get_es_client_config():
    """Get Elasticsearch client configuration dict."""
    config = {
        "hosts": [f"{'https' if ES_USE_SSL else 'http'}://{ES_HOST}:{ES_PORT}"],
        "request_timeout": 60,
    }
    
    if ES_USE_SSL and not ES_VERIFY_CERTS:
        config["verify_certs"] = False
    
    if ES_USERNAME and ES_PASSWORD:
        config["basic_auth"] = (ES_USERNAME, ES_PASSWORD)
    
    return config


def get_llm_headers():
    """Get headers for LLM API requests."""
    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"
    return headers


def print_config():
    """Print current configuration (for debugging)."""
    print("Current Configuration:")
    print(f"  ES_HOST: {ES_HOST}")
    print(f"  ES_PORT: {ES_PORT}")
    print(f"  ES_INDEX_PATTERN: {ES_INDEX_PATTERN}")
    print(f"  LLM_HOST: {LLM_HOST}")
    print(f"  LLM_PORT: {LLM_PORT}")
    print(f"  EXCLUDE_TYPES: {EXCLUDE_TYPES}")
    print(f"  OUTPUT_DIR: {OUTPUT_DIR}")
    print(f"  CACHE_FILE: {CACHE_FILE}")


if __name__ == "__main__":
    print_config()
