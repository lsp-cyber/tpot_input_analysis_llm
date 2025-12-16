# Configuration Guide

This guide explains all configuration options for the T-Pot Honeypot Analyzer.

## Configuration Methods

Settings can be configured through multiple methods (in order of priority):

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **`.env` file** (requires python-dotenv)
4. **`config.yml` file**
5. **Default values** (lowest priority)

## Quick Setup

```bash
# Copy example config
cp config.example.yml config.yml

# Edit with your settings
nano config.yml
```

## Configuration Reference

### Elasticsearch Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `elasticsearch.host` | `ES_HOST` | `localhost` | T-Pot Elasticsearch host IP/hostname |
| `elasticsearch.port` | `ES_PORT` | `64298` | Elasticsearch port (T-Pot default: 64298) |
| `elasticsearch.index_pattern` | `ES_INDEX_PATTERN` | `logstash-*` | Index pattern to search |
| `elasticsearch.timeout` | `ES_TIMEOUT` | `60` | Query timeout in seconds |
| `elasticsearch.max_results` | `ES_MAX_RESULTS` | `100000` | Maximum logs to retrieve |
| `elasticsearch.use_ssl` | `ES_USE_SSL` | `false` | Enable SSL/TLS |
| `elasticsearch.verify_certs` | `ES_VERIFY_CERTS` | `true` | Verify SSL certificates |
| `elasticsearch.username` | `ES_USERNAME` | `""` | Basic auth username |
| `elasticsearch.password` | `ES_PASSWORD` | `""` | Basic auth password |

#### Finding Your T-Pot Elasticsearch

T-Pot exposes Elasticsearch on port **64298** by default. To find your T-Pot's IP:

```bash
# On the T-Pot host
ip addr show | grep inet
```

Test connectivity:
```bash
curl http://your-tpot-ip:64298/_cluster/health
```

### LM Studio / LLM Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `lm_studio.host` | `LLM_HOST` | `localhost` | LM Studio host IP/hostname |
| `lm_studio.port` | `LLM_PORT` | `1234` | LM Studio API port |
| `lm_studio.timeout` | `LLM_TIMEOUT` | `120` | Request timeout in seconds |
| `lm_studio.delay_between_requests` | `LLM_DELAY` | `0.5` | Delay between sequential requests |
| `lm_studio.temperature` | `LLM_TEMPERATURE` | `0.3` | Generation temperature (0.0-1.0) |
| `lm_studio.max_tokens` | `LLM_MAX_TOKENS` | `1000` | Maximum tokens per response |
| `lm_studio.model` | `LLM_MODEL` | `""` | Specific model name (optional) |
| `lm_studio.api_key` | `LLM_API_KEY` | `""` | API key (if required) |

#### LM Studio Setup

1. Download [LM Studio](https://lmstudio.ai/)
2. Download a model (recommended: Qwen 2.5 Coder 7B or Llama 3 8B)
3. Load the model in LM Studio
4. Start the local server (default port: 1234)
5. Enable "Allow network access" if running on a different machine

#### Using Other OpenAI-Compatible APIs

The tool works with any OpenAI-compatible API. Set the full URL:

```bash
export LLM_API_URL="http://your-server:port/v1/chat/completions"
export LLM_API_KEY="your-api-key"
```

### Analysis Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `analysis.lookback_hours` | `LOOKBACK_HOURS` | - | Hours to look back |
| `analysis.lookback_days` | `LOOKBACK_DAYS` | `1` | Days to look back |
| `analysis.min_commands` | `MIN_COMMANDS` | `2` | Minimum commands per session |
| `analysis.max_sessions` | `MAX_SESSIONS` | `null` | Maximum sessions to analyze |
| `analysis.exclude_types` | `EXCLUDE_TYPES` | `Fatt,Suricata,P0f` | Honeypot types to exclude |
| `analysis.output_dir` | `OUTPUT_DIR` | `output` | Output directory |

#### Time Range Options

You can specify the time range in three ways:

**In config.yml:**
```yaml
analysis:
  lookback_hours: 24   # OR
  lookback_days: 7     # If both set, hours takes precedence
```

**Via command line:**
```bash
python run_analysis.py --hours 12
python run_analysis.py --days 7
```

**Via environment:**
```bash
LOOKBACK_HOURS=24 python run_analysis.py
```

## Command-Line Arguments

### run_analysis.py

```
usage: run_analysis.py [-h] [--hours HOURS] [--days DAYS] 
                       [--output-dir OUTPUT_DIR] [--min-commands MIN_COMMANDS]
                       [--max-sessions MAX_SESSIONS] [--workers WORKERS]
                       [--show-config]

Options:
  --hours HOURS         Hours to look back (overrides config)
  --days DAYS           Days to look back (overrides config)
  --output-dir DIR      Output directory (default: from config)
  --min-commands N      Minimum commands per session (default: from config)
  --max-sessions N      Maximum sessions to analyze (default: unlimited)
  --workers N           Parallel workers for LLM (default: 1)
  --show-config         Display current configuration and exit
```

### query_tpot_es.py

```
usage: query_tpot_es.py [-h] [--hours HOURS] [--days DAYS]
                        [--max-results MAX] [--output FILE] [--llm-output FILE]

Options:
  --hours HOURS         Hours to look back
  --days DAYS           Days to look back
  --max-results MAX     Maximum log entries to retrieve
  --output FILE         Output JSON file (default: sessions.json)
  --llm-output FILE     Output text file (default: sessions_for_llm.txt)
```

### analyze_sessions.py

```
usage: analyze_sessions.py [-h] [--input FILE] [--output FILE] [--report FILE]
                           [--summary FILE] [--model MODEL] [--limit N]
                           [--min-commands N] [--workers N]

Options:
  --input FILE          Input sessions JSON (default: sessions.json)
  --output FILE         Output results JSON (default: analysis_results.json)
  --report FILE         Output markdown report (default: analysis_report.md)
  --summary FILE        Output executive summary (default: {report}_summary.md)
  --model MODEL         Specific LLM model to use
  --limit N             Maximum sessions to analyze
  --min-commands N      Minimum commands per session
  --workers N           Parallel workers (default: 1)
```

## Environment Variables

All settings can be set via environment variables:

```bash
# Elasticsearch
export ES_HOST="10.0.0.75"
export ES_PORT="64298"
export ES_INDEX_PATTERN="logstash-*"
export ES_TIMEOUT="60"
export ES_MAX_RESULTS="100000"
export ES_USE_SSL="false"
export ES_VERIFY_CERTS="true"
export ES_USERNAME=""
export ES_PASSWORD=""

# LLM
export LLM_HOST="10.0.0.72"
export LLM_PORT="1234"
export LLM_TIMEOUT="120"
export LLM_DELAY="0.5"
export LLM_TEMPERATURE="0.3"
export LLM_MAX_TOKENS="1000"
export LLM_MODEL=""
export LLM_API_KEY=""
export LLM_API_URL="http://localhost:1234/v1/chat/completions"

# Analysis
export LOOKBACK_HOURS="24"
export LOOKBACK_DAYS="7"
export MIN_COMMANDS="2"
export MAX_SESSIONS=""
export EXCLUDE_TYPES="Fatt,Suricata,P0f"
export OUTPUT_DIR="output"
```

## Using a .env File

Create a `.env` file in the project directory:

```bash
# .env file
ES_HOST=10.0.0.75
ES_PORT=64298
LLM_HOST=10.0.0.72
LLM_PORT=1234
LOOKBACK_HOURS=24
```

The `.env` file is automatically loaded if `python-dotenv` is installed.

## Example Configurations

### Minimal Setup (Local Testing)

```yaml
# config.yml - minimal
elasticsearch:
  host: "localhost"
  port: 64298

lm_studio:
  host: "localhost"
  port: 1234

analysis:
  lookback_hours: 1
  max_sessions: 10
```

### Production Setup

```yaml
# config.yml - production
elasticsearch:
  host: "192.168.1.100"
  port: 64298
  timeout: 120
  max_results: 500000

lm_studio:
  host: "192.168.1.50"
  port: 1234
  timeout: 180
  temperature: 0.2

analysis:
  lookback_days: 1
  min_commands: 2
  max_sessions: null
  output_dir: "/var/log/honeypot-analysis"
```

### High-Volume Analysis

```yaml
# config.yml - high volume
elasticsearch:
  host: "tpot-server"
  port: 64298
  max_results: 1000000

lm_studio:
  host: "gpu-server"
  port: 1234
  timeout: 300

analysis:
  lookback_days: 7
  min_commands: 3
```

Run with parallel processing:
```bash
python run_analysis.py --workers 8
```

## Verifying Configuration

Display current configuration:

```bash
python run_analysis.py --show-config
```

Output:
```
============================================================
CURRENT CONFIGURATION
============================================================

Elasticsearch:
  Host: 10.0.0.75
  Port: 64298
  Index Pattern: logstash-*
  Timeout: 60s
  Max Results: 100,000

LM Studio:
  Host: 10.0.0.72
  Port: 1234
  API URL: http://10.0.0.72:1234/v1/chat/completions
  Timeout: 120s
  Temperature: 0.3
  Max Tokens: 1000

Analysis:
  Lookback: 24 hours (1.0 days)
  Min Commands: 2
  Max Sessions: unlimited
  Exclude Types: ['Fatt', 'Suricata', 'P0f']

Output:
  Output Dir: output
============================================================
```

## Security Considerations

1. **Never commit `config.yml`** with real credentials to git
2. **Use `.env` files** for sensitive data (add to `.gitignore`)
3. **Restrict Elasticsearch access** to trusted networks
4. **Use SSL** for remote Elasticsearch connections when possible
