# T-Pot Honeypot Analyzer

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Automated threat analysis of shell commands captured by [T-Pot](https://github.com/telekom-security/tpotce) honeypots using local LLMs via [LM Studio](https://lmstudio.ai/).

## Overview

This tool automates the analysis of attacker activity captured by T-Pot honeypots:

1. **Extract** - Queries T-Pot's Elasticsearch for shell command logs
2. **Aggregate** - Groups commands by attacker session
3. **Analyze** - Sends sessions to a local LLM for threat classification
4. **Report** - Generates detailed reports with IOCs, attack types, and recommendations

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   T-Pot     │────▶│ Elasticsearch│────▶│  Analyzer   │────▶│   Reports   │
│ Honeypots   │     │    Logs     │     │  (LLM)      │     │  (MD/JSON)  │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

## Features

- 🔍 **Session Aggregation** - Groups individual commands into complete attack sessions
- 🤖 **LLM-Powered Analysis** - Uses local LLMs for private, cost-free analysis
- ⚡ **Parallel Processing** - Analyze hundreds of sessions quickly with multi-threading
- 📊 **Rich Reports** - Executive summaries with IOCs, MITRE ATT&CK techniques, and action items
- 🌍 **GeoIP Enrichment** - Attack source geography from T-Pot's built-in enrichment
- ⏰ **Automation Ready** - Designed for cron scheduling

## Supported Honeypots

Analyzes input from honeypots that capture shell commands:

| Honeypot | Description | Data Captured |
|----------|-------------|---------------|
| **Cowrie** | SSH/Telnet | Shell commands, credentials |
| **Adbhoney** | Android Debug Bridge | ADB commands, malware drops |
| **Dicompot** | DICOM (Medical) | DICOM protocol commands |

## Quick Start

### Prerequisites

- Python 3.8+
- Running T-Pot instance with Elasticsearch
- [LM Studio](https://lmstudio.ai/) with a loaded model (or compatible OpenAI API endpoint)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/tpot-honeypot-analyzer.git
cd tpot-honeypot-analyzer

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Copy and edit configuration
cp config.example.yml config.yml
nano config.yml  # Edit with your settings
```

### Configuration

Edit `config.yml` with your environment settings:

```yaml
elasticsearch:
  host: "your-tpot-ip"     # T-Pot Elasticsearch host
  port: 64298              # Default T-Pot ES port

lm_studio:
  host: "your-lmstudio-ip" # LM Studio host
  port: 1234               # Default LM Studio port

analysis:
  lookback_hours: 24       # Time window to analyze
  min_commands: 2          # Filter noise
```

See [Configuration Guide](docs/CONFIGURATION.md) for all options.

### Run Analysis

```bash
# Full pipeline with config.yml settings
python run_analysis.py

# Override time range
python run_analysis.py --hours 12
python run_analysis.py --days 7

# Parallel processing (faster)
python run_analysis.py --hours 24 --workers 4

# View current configuration
python run_analysis.py --show-config
```

### Output

Results are saved to `output/<timestamp>/`:

```
output/20251216_162229/
├── sessions.json              # Raw session data
├── sessions_for_llm.txt       # Human-readable session list
├── analysis_results.json      # Full LLM analysis results
├── analysis_report.md         # Detailed report (all sessions)
└── analysis_report_summary.md # Executive summary
```

A `latest` symlink always points to the most recent run.

## Documentation

- [Configuration Guide](docs/CONFIGURATION.md) - All configuration options explained
- [Output Guide](docs/OUTPUT_GUIDE.md) - Understanding the reports and JSON output
- [Architecture](docs/ARCHITECTURE.md) - System design and data flow

## Example Output

### Executive Summary

The tool generates an executive summary with:

- **Key Metrics** - Total sessions, unique IPs, time window
- **Threat Levels** - Distribution of Low/Medium/High severity
- **Attack Types** - Reconnaissance, backdoors, cryptominers, etc.
- **Top Attackers** - Most active source IPs
- **Techniques** - MITRE ATT&CK aligned (SSH injection, persistence, etc.)
- **IOCs** - SSH keys, URLs, malware indicators
- **Recommendations** - Prioritized action items

### Sample Analysis

```
Session: 9c3c7fe143c3
Honeypot: Cowrie (SSH)
Attacker: 132.145.213.106 (United States - Oracle Cloud)

Attack Type: Backdoor/SSH Key Injection
Threat Level: High

Techniques:
- SSH key injection for persistent access
- Password change for credential takeover
- File attribute manipulation (chattr -ia)
- System reconnaissance (uname, /proc/cpuinfo)

IOCs:
- SSH Key: ssh-rsa AAAAB3NzaC1yc2E... (mdrfckr)
- Password: fjqrH2qBHEqU
```

## Automation

### Cron Examples

```bash
# Every 6 hours
0 */6 * * * cd /path/to/analyzer && .venv/bin/python run_analysis.py --hours 6 >> /var/log/honeypot.log 2>&1

# Daily analysis of last 24 hours
0 0 * * * cd /path/to/analyzer && .venv/bin/python run_analysis.py --hours 24 --workers 4 >> /var/log/honeypot.log 2>&1

# Weekly deep analysis
0 0 * * 0 cd /path/to/analyzer && .venv/bin/python run_analysis.py --days 7 >> /var/log/honeypot.log 2>&1
```

## Project Structure

```
tpot-honeypot-analyzer/
├── run_analysis.py       # Main orchestration script
├── query_tpot_es.py      # Elasticsearch query module
├── analyze_sessions.py   # LLM analysis module
├── explore_tpot_es.py    # ES exploration utility
├── config.py             # Configuration loader
├── config.yml            # Your configuration (git-ignored)
├── config.example.yml    # Example configuration
├── requirements.txt      # Python dependencies
├── output/               # Analysis results (git-ignored)
│   └── latest -> ...     # Symlink to most recent run
└── docs/
    ├── CONFIGURATION.md  # Configuration reference
    ├── OUTPUT_GUIDE.md   # Output interpretation guide
    └── ARCHITECTURE.md   # System architecture
```

## Requirements

- **T-Pot** - Tested with T-Pot 22.x and 23.x
- **Elasticsearch** - T-Pot's built-in ES (port 64298 by default)
- **LM Studio** - Any OpenAI-compatible API endpoint works
- **Python** - 3.8 or higher

### Recommended LLM Models

Tested models (via LM Studio):

| Model | Speed | Quality | Notes |
|-------|-------|---------|-------|
| Qwen 2.5 Coder 7B | Fast | Good | Good balance for high volume |
| Llama 3 8B | Fast | Good | General purpose |
| Mistral 7B | Fast | Good | Efficient |
| Qwen 2.5 32B | Slow | Excellent | Best classification accuracy |
| Llama 3 70B | Slow | Excellent | Highest quality |

For best results with high session volumes, use parallel processing with a faster model.

## Troubleshooting

### Connection Issues

```bash
# Test Elasticsearch connection
python query_tpot_es.py --hours 1 --max-results 10

# Test LM Studio connection
python analyze_sessions.py --limit 1
```

### Common Problems

| Issue | Solution |
|-------|----------|
| Connection refused (ES) | Check `elasticsearch.host` and `port` in config.yml |
| Connection refused (LLM) | Ensure LM Studio is running with a model loaded |
| No sessions found | Increase time range or verify honeypot is receiving traffic |
| Slow analysis | Use `--workers 4` for parallel processing |
| High "Unknown" rate | Try a larger/better LLM model |

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [T-Pot](https://github.com/telekom-security/tpotce) by Deutsche Telekom Security
- [LM Studio](https://lmstudio.ai/) for local LLM inference
- [Cowrie](https://github.com/cowrie/cowrie) honeypot project
