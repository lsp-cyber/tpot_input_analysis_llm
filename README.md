# T-Pot Honeypot Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Automated analysis of shell commands captured by [T-Pot](https://github.com/telekom-security/tpotce) honeypots using Large Language Models (LLMs).

## Overview

This tool queries your T-Pot Elasticsearch instance for interactive shell sessions, groups commands by attack pattern, and uses an LLM to analyze attacker behavior and extract threat intelligence.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   T-Pot Hive    │     │   This Tool     │     │   LLM Server    │
│  (Elasticsearch)│────▶│                 │────▶│  (LM Studio)    │
│                 │     │  • Query logs   │     │                 │
│  • Cowrie       │     │  • Deduplicate  │     │  • Analyze      │
│  • Adbhoney     │     │  • Aggregate    │     │  • Classify     │
│  • Dicompot     │     │  • Cache        │     │  • Extract IOCs │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                │
                                ▼
                        ┌─────────────────┐
                        │    Reports      │
                        │  • JSON         │
                        │  • Markdown     │
                        └─────────────────┘
```

## Features

- **Smart Deduplication**: Automated attacks often use identical scripts. We fingerprint command sequences and only analyze unique patterns, dramatically reducing LLM calls.
- **Caching**: Analyses are cached locally, so re-running on the same attack patterns is instant.
- **Pattern-Based Reports**: Reports group sessions by attack pattern, showing how many IPs used the same attack script.
- **LLM-Powered Analysis**: Get automated threat classification, technique identification, and IOC extraction.
- **Flexible LLM Backend**: Works with LM Studio, Ollama, or any OpenAI-compatible API.

## Supported Honeypots

The tool focuses on honeypots that capture shell commands:

| Honeypot | Type | Description |
|----------|------|-------------|
| **Cowrie** | SSH/Telnet | Medium-interaction SSH honeypot |
| **Adbhoney** | Android | Android Debug Bridge honeypot |
| **Dicompot** | Medical | DICOM medical imaging honeypot |

Network analysis tools (Suricata, P0f, Fatt) are automatically excluded as they don't capture interactive shell sessions.

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/tpot-honeypot-analyzer.git
cd tpot-honeypot-analyzer
```

### 2. Install Dependencies

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure

Copy the example environment file and edit with your settings:

```bash
cp .env.example .env
```

Edit `.env` with your T-Pot and LLM server details:

```bash
# T-Pot Elasticsearch
ES_HOST=your-tpot-hive-ip
ES_PORT=64298

# LLM Server (LM Studio, Ollama, etc.)
LLM_HOST=your-llm-server-ip
LLM_PORT=1234
```

### 4. Test Your Connection

```bash
python explore_tpot_es.py
```

This will show you:
- All honeypot types in your T-Pot
- Which ones have captured shell commands
- Sample data to verify everything works

### 5. Run Analysis

```bash
# Full pipeline: query + analyze
python run_analysis.py --hours 12

# Or run steps separately:
python query_tpot_es.py --hours 12
python analyze_sessions.py --input sessions.json
```

## Configuration

### Environment Variables

All configuration is done through environment variables or a `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `ES_HOST` | `localhost` | T-Pot Elasticsearch host |
| `ES_PORT` | `64298` | Elasticsearch port |
| `ES_INDEX_PATTERN` | `logstash-*` | Index pattern to query |
| `ES_USE_SSL` | `false` | Use HTTPS for ES connection |
| `ES_USERNAME` | `` | ES username (if auth enabled) |
| `ES_PASSWORD` | `` | ES password (if auth enabled) |
| `LLM_HOST` | `localhost` | LLM server host |
| `LLM_PORT` | `1234` | LLM server port |
| `LLM_MODEL` | `` | Specific model to use (optional) |
| `LLM_API_KEY` | `` | API key for commercial LLMs |
| `EXCLUDE_TYPES` | `Fatt,Suricata,P0f` | Honeypot types to exclude |

### LLM Server Setup

This tool works with any OpenAI-compatible API. We recommend:

#### LM Studio (Recommended for local)

1. Download [LM Studio](https://lmstudio.ai/)
2. Download a model (e.g., Mistral 7B, Llama 2)
3. Go to **Developer** tab → **Start Server**
4. Note the host/port (default: `localhost:1234`)

#### Ollama

```bash
ollama serve
# In .env: LLM_PORT=11434
```

#### OpenAI API

```bash
# In .env:
LLM_API_URL=https://api.openai.com/v1/chat/completions
LLM_MODEL=gpt-4
LLM_API_KEY=sk-...
```

## Usage

### Full Pipeline

```bash
# Analyze last 12 hours (default)
python run_analysis.py

# Analyze last 24 hours
python run_analysis.py --hours 24

# Limit sessions for testing
python run_analysis.py --hours 12 --max-sessions 50
```

### Individual Scripts

```bash
# Query T-Pot ES only
python query_tpot_es.py --hours 12 --output my_sessions.json

# Analyze existing session file
python analyze_sessions.py --input my_sessions.json --limit 10

# Explore your data
python explore_tpot_es.py
```

### Cache Management

```bash
# Use cache (default)
python analyze_sessions.py --input sessions.json

# Clear cache and re-analyze everything
python analyze_sessions.py --input sessions.json --clear-cache

# Bypass cache entirely
python analyze_sessions.py --input sessions.json --no-cache
```

## Scheduled Analysis (Cron)

Add to crontab for automated analysis:

```bash
crontab -e
```

```bash
# Every 12 hours (midnight and noon)
0 0,12 * * * cd /path/to/tpot-honeypot-analyzer && /path/to/.venv/bin/python run_analysis.py --hours 12 >> /var/log/honeypot-analysis.log 2>&1

# Every 6 hours
0 */6 * * * cd /path/to/tpot-honeypot-analyzer && /path/to/.venv/bin/python run_analysis.py --hours 6 >> /var/log/honeypot-analysis.log 2>&1
```

## Output

### Directory Structure

```
output/
├── 20241215_120000/
│   ├── sessions.json           # Raw session data from ES
│   ├── sessions_for_llm.txt    # Human-readable session list
│   ├── analysis_results.json   # Full analysis results
│   └── analysis_report.md      # Markdown summary report
├── 20241215_000000/
│   └── ...
└── latest -> 20241215_120000   # Symlink to most recent
```

### Sample Report Output

The markdown report groups attacks by pattern:

```markdown
# Honeypot Attack Analysis Report

## Summary
- Total Sessions Analyzed: 348
- Unique Attack Patterns: 52
- Successful Analyses: 52

## Attack Patterns (52 unique)

### Pattern: a3f8b2c1...
- **Sessions**: 87
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 23

#### Analysis
**Attack Type**: Botnet Recruitment (Mirai variant)
**Objective**: Download and execute malware to join botnet
**Techniques**: wget/curl payload download, chmod +x, process execution
**IOCs**:
- URLs: http://94.154.35.154/arm.uhavenobotsxd
- Filenames: arm.uhavenobotsxd, arm5.uhavenobotsxd
**Threat Level**: High
```

## Project Structure

```
tpot-honeypot-analyzer/
├── config.py              # Centralized configuration
├── query_tpot_es.py       # Query Elasticsearch for sessions
├── analyze_sessions.py    # LLM analysis with deduplication
├── run_analysis.py        # Orchestration script for cron
├── explore_tpot_es.py     # Data exploration utility
├── requirements.txt       # Python dependencies
├── .env.example           # Example configuration
├── .gitignore
├── LICENSE
└── README.md
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Ideas for Contributions

- [ ] Web dashboard for browsing results
- [ ] IOC auto-extraction to STIX/MISP format
- [ ] VirusTotal/AbuseIPDB integration
- [ ] Slack/email alerting for new attack patterns
- [ ] Fuzzy matching for similar (not identical) attacks
- [ ] Geographic visualization of attack sources

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [T-Pot](https://github.com/telekom-security/tpotce) by Deutsche Telekom Security
- [LM Studio](https://lmstudio.ai/) for easy local LLM hosting
- The honeypot community for ongoing threat research

## Disclaimer

This tool is for security research and threat intelligence purposes. Always follow responsible disclosure practices and applicable laws when analyzing attack data.
