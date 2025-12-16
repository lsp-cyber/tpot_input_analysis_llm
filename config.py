#!/usr/bin/env python3
"""
config.py - Centralized configuration for T-Pot Honeypot Analyzer

Configuration priority (highest to lowest):
1. Environment variables
2. .env file (if python-dotenv installed)
3. config.yml file
4. Default values

Usage:
    from config import config
    
    # Access settings:
    config.elasticsearch.host
    config.elasticsearch.port
    config.lm_studio.host
    config.analysis.lookback_hours
"""

import os
from pathlib import Path

# =============================================================================
# Load config.yml
# =============================================================================
def load_yaml_config():
    """Load configuration from config.yml if it exists."""
    config_path = Path(__file__).parent / "config.yml"
    
    if not config_path.exists():
        print(f"Warning: config.yml not found at {config_path}")
        return {}
    
    try:
        import yaml
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        print("Warning: PyYAML not installed. Install with: pip install pyyaml")
        return {}
    except Exception as e:
        print(f"Warning: Failed to load config.yml: {e}")
        return {}

# Load YAML config first
_yaml_config = load_yaml_config()

# =============================================================================
# Load .env file (optional, overrides yaml)
# =============================================================================
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, that's fine

# =============================================================================
# Helper functions
# =============================================================================
def _get_yaml(section, key, default=None):
    """Get a value from the yaml config."""
    if section in _yaml_config and key in _yaml_config[section]:
        return _yaml_config[section][key]
    return default

def get_config(env_var, yaml_section, yaml_key, default, cast=str):
    """Get config value with priority: env var > yaml > default"""
    # Check environment variable first
    env_value = os.getenv(env_var)
    if env_value is not None:
        if cast == bool:
            return env_value.lower() in ('true', '1', 'yes')
        return cast(env_value)
    
    # Check yaml config
    yaml_value = _get_yaml(yaml_section, yaml_key)
    if yaml_value is not None:
        return cast(yaml_value) if cast != bool else bool(yaml_value)
    
    # Return default
    return default

# =============================================================================
# Configuration Classes
# =============================================================================
class ElasticsearchConfig:
    """Elasticsearch connection settings."""
    def __init__(self):
        self.host = get_config("ES_HOST", "elasticsearch", "host", "localhost")
        self.port = get_config("ES_PORT", "elasticsearch", "port", 64298, int)
        self.index_pattern = get_config("ES_INDEX_PATTERN", "elasticsearch", "index_pattern", "logstash-*")
        self.timeout = get_config("ES_TIMEOUT", "elasticsearch", "timeout", 60, int)
        self.max_results = get_config("ES_MAX_RESULTS", "elasticsearch", "max_results", 10000, int)
        self.use_ssl = get_config("ES_USE_SSL", "elasticsearch", "use_ssl", False, bool)
        self.verify_certs = get_config("ES_VERIFY_CERTS", "elasticsearch", "verify_certs", True, bool)
        self.username = get_config("ES_USERNAME", "elasticsearch", "username", "")
        self.password = get_config("ES_PASSWORD", "elasticsearch", "password", "")
    
    def get_client_config(self):
        """Get Elasticsearch client configuration dict."""
        config = {
            "hosts": [f"{'https' if self.use_ssl else 'http'}://{self.host}:{self.port}"],
            "request_timeout": self.timeout,
        }
        
        if self.use_ssl and not self.verify_certs:
            config["verify_certs"] = False
        
        if self.username and self.password:
            config["basic_auth"] = (self.username, self.password)
        
        return config


class LMStudioConfig:
    """LM Studio / LLM connection settings."""
    def __init__(self):
        self.host = get_config("LLM_HOST", "lm_studio", "host", "localhost")
        self.port = get_config("LLM_PORT", "lm_studio", "port", 1234, int)
        self.timeout = get_config("LLM_TIMEOUT", "lm_studio", "timeout", 120, int)
        self.delay_between_requests = get_config("LLM_DELAY", "lm_studio", "delay_between_requests", 0.5, float)
        self.temperature = get_config("LLM_TEMPERATURE", "lm_studio", "temperature", 0.3, float)
        self.max_tokens = get_config("LLM_MAX_TOKENS", "lm_studio", "max_tokens", 1000, int)
        self.model = get_config("LLM_MODEL", "lm_studio", "model", "")
        self.api_key = get_config("LLM_API_KEY", "lm_studio", "api_key", "")
        
        # Build URLs
        base_url = f"http://{self.host}:{self.port}"
        self.api_url = os.getenv("LLM_API_URL", f"{base_url}/v1/chat/completions")
        self.models_url = f"{base_url}/v1/models"
    
    def get_headers(self):
        """Get headers for LLM API requests."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers


class AnalysisConfig:
    """Analysis settings."""
    def __init__(self):
        # Time range - check for hours first, then days
        self._yaml_hours = _get_yaml("analysis", "lookback_hours")
        self._yaml_days = _get_yaml("analysis", "lookback_days")
        
        # Store the raw values for display purposes
        self.lookback_hours = self._yaml_hours
        self.lookback_days = self._yaml_days
        
        # Calculate total_hours (the actual value to use)
        if os.getenv("LOOKBACK_HOURS"):
            self.total_hours = int(os.getenv("LOOKBACK_HOURS"))
        elif os.getenv("LOOKBACK_DAYS"):
            self.total_hours = int(os.getenv("LOOKBACK_DAYS")) * 24
        elif self._yaml_hours is not None:
            self.total_hours = int(self._yaml_hours)
        elif self._yaml_days is not None:
            self.total_hours = int(self._yaml_days) * 24
        else:
            self.total_hours = 12  # Default
        
        self.min_commands = get_config("MIN_COMMANDS", "analysis", "min_commands", 2, int)
        
        # Max sessions (None = no limit)
        self.max_sessions = _get_yaml("analysis", "max_sessions")
        if os.getenv("MAX_SESSIONS"):
            self.max_sessions = int(os.getenv("MAX_SESSIONS"))
        
        # Honeypot types to exclude
        _default_exclude = ["Fatt", "Suricata", "P0f"]
        self.exclude_types = _get_yaml("analysis", "exclude_types") or _default_exclude
        if os.getenv("EXCLUDE_TYPES"):
            self.exclude_types = os.getenv("EXCLUDE_TYPES").split(",")
        
        # Honeypot types known to have 'input' field
        self.input_types = ["Cowrie", "Adbhoney", "Dicompot"]
        
        # Output settings
        self.output_dir = Path(get_config("OUTPUT_DIR", "analysis", "output_dir", "output"))
        self.cache_file = Path(get_config("CACHE_FILE", "analysis", "cache_file", "analysis_cache.json"))


class Config:
    """Main configuration container."""
    def __init__(self):
        self.elasticsearch = ElasticsearchConfig()
        self.lm_studio = LMStudioConfig()
        self.analysis = AnalysisConfig()
    
    def print_config(self):
        """Print current configuration (for debugging)."""
        print("\n" + "=" * 60)
        print("CURRENT CONFIGURATION")
        print("=" * 60)
        
        print("\nElasticsearch:")
        print(f"  Host: {self.elasticsearch.host}")
        print(f"  Port: {self.elasticsearch.port}")
        print(f"  Index Pattern: {self.elasticsearch.index_pattern}")
        print(f"  Timeout: {self.elasticsearch.timeout}s")
        print(f"  Max Results: {self.elasticsearch.max_results:,}")
        
        print("\nLM Studio:")
        print(f"  Host: {self.lm_studio.host}")
        print(f"  Port: {self.lm_studio.port}")
        print(f"  API URL: {self.lm_studio.api_url}")
        print(f"  Models URL: {self.lm_studio.models_url}")
        print(f"  Timeout: {self.lm_studio.timeout}s")
        print(f"  Temperature: {self.lm_studio.temperature}")
        print(f"  Max Tokens: {self.lm_studio.max_tokens}")
        
        print("\nAnalysis:")
        print(f"  Lookback: {self.analysis.total_hours} hours ({self.analysis.total_hours/24:.1f} days)")
        if self.analysis.lookback_hours:
            print(f"    (from config: lookback_hours={self.analysis.lookback_hours})")
        elif self.analysis.lookback_days:
            print(f"    (from config: lookback_days={self.analysis.lookback_days})")
        print(f"  Min Commands: {self.analysis.min_commands}")
        print(f"  Max Sessions: {self.analysis.max_sessions or 'unlimited'}")
        print(f"  Exclude Types: {self.analysis.exclude_types}")
        
        print("\nOutput:")
        print(f"  Output Dir: {self.analysis.output_dir}")
        print(f"  Cache File: {self.analysis.cache_file}")
        
        print("=" * 60 + "\n")


# =============================================================================
# Create global config instance
# =============================================================================
config = Config()

# =============================================================================
# Legacy exports (for backwards compatibility)
# =============================================================================
ES_HOST = config.elasticsearch.host
ES_PORT = config.elasticsearch.port
ES_INDEX_PATTERN = config.elasticsearch.index_pattern
ES_TIMEOUT = config.elasticsearch.timeout
ES_MAX_RESULTS = config.elasticsearch.max_results
ES_USE_SSL = config.elasticsearch.use_ssl
ES_VERIFY_CERTS = config.elasticsearch.verify_certs
ES_USERNAME = config.elasticsearch.username
ES_PASSWORD = config.elasticsearch.password

LLM_HOST = config.lm_studio.host
LLM_PORT = config.lm_studio.port
LLM_TIMEOUT = config.lm_studio.timeout
LLM_DELAY = config.lm_studio.delay_between_requests
LLM_TEMPERATURE = config.lm_studio.temperature
LLM_MAX_TOKENS = config.lm_studio.max_tokens
LLM_API_URL = config.lm_studio.api_url
LLM_MODEL = config.lm_studio.model
LLM_API_KEY = config.lm_studio.api_key

LOOKBACK_HOURS = config.analysis.total_hours
MIN_COMMANDS = config.analysis.min_commands
MAX_SESSIONS = config.analysis.max_sessions
EXCLUDE_TYPES = config.analysis.exclude_types
INPUT_TYPES = config.analysis.input_types
OUTPUT_DIR = config.analysis.output_dir
CACHE_FILE = config.analysis.cache_file

# Legacy function exports
def get_es_client_config():
    return config.elasticsearch.get_client_config()

def get_llm_headers():
    return config.lm_studio.get_headers()

def print_config():
    config.print_config()


if __name__ == "__main__":
    config.print_config()
