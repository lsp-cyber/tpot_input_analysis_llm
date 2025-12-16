# Architecture

This document describes the system architecture and data flow of the T-Pot Honeypot Analyzer.

## System Overview

```mermaid
flowchart TB
    subgraph Internet["Internet"]
        Attackers[("👤 Attackers")]
    end

    subgraph TPot["T-Pot Honeypot Platform"]
        Cowrie["🐚 Cowrie\n(SSH/Telnet)"]
        Adbhoney["📱 Adbhoney\n(Android ADB)"]
        Dicompot["🏥 Dicompot\n(DICOM)"]
        ES[("🔍 Elasticsearch\n:64298")]
    end

    subgraph Analyzer["Honeypot Analyzer"]
        Query["📥 query_tpot_es.py\n(Data Extraction)"]
        Analyze["🤖 analyze_sessions.py\n(LLM Analysis)"]
        Report["📊 Reports\n(MD/JSON)"]
    end

    subgraph LLM["LLM Server"]
        LMStudio["🧠 LM Studio\n:1234"]
    end

    Attackers -->|"Attack Traffic"| Cowrie
    Attackers -->|"Attack Traffic"| Adbhoney
    Attackers -->|"Attack Traffic"| Dicompot
    
    Cowrie -->|"Logs"| ES
    Adbhoney -->|"Logs"| ES
    Dicompot -->|"Logs"| ES
    
    ES -->|"Query"| Query
    Query -->|"Sessions"| Analyze
    Analyze <-->|"API Calls"| LMStudio
    Analyze -->|"Generate"| Report
```

## Component Details

### T-Pot Platform

T-Pot is a multi-honeypot platform that captures attack traffic:

```mermaid
flowchart LR
    subgraph Honeypots["Honeypot Layer"]
        C["Cowrie"]
        A["Adbhoney"]
        D["Dicompot"]
        O["Others..."]
    end
    
    subgraph Storage["Data Layer"]
        ES[("Elasticsearch")]
        Kibana["Kibana"]
    end
    
    C --> ES
    A --> ES
    D --> ES
    O --> ES
    ES --> Kibana
```

**Relevant Honeypots for This Tool:**

| Honeypot | Port | Captures |
|----------|------|----------|
| Cowrie | 22, 23 | SSH/Telnet shell commands |
| Adbhoney | 5555 | Android Debug Bridge commands |
| Dicompot | 11112 | DICOM protocol commands |

### Analyzer Pipeline

```mermaid
flowchart TB
    subgraph Input["Data Collection"]
        ES[("Elasticsearch")]
        Query["query_tpot_es.py"]
    end
    
    subgraph Process["Processing"]
        Sessions["sessions.json"]
        Filter["Filter\n(min_commands)"]
        Analyze["analyze_sessions.py"]
    end
    
    subgraph LLM["Analysis"]
        Prompt["Build Prompt"]
        API["LLM API Call"]
        Parse["Parse Response"]
    end
    
    subgraph Output["Reports"]
        JSON["analysis_results.json"]
        Report["analysis_report.md"]
        Summary["analysis_report_summary.md"]
    end
    
    ES -->|"Query with\ntime range"| Query
    Query -->|"Group by\nsession"| Sessions
    Sessions --> Filter
    Filter -->|"Filtered\nsessions"| Analyze
    
    Analyze --> Prompt
    Prompt --> API
    API --> Parse
    Parse --> Analyze
    
    Analyze --> JSON
    Analyze --> Report
    Analyze --> Summary
```

## Data Flow

### 1. Data Extraction (query_tpot_es.py)

```mermaid
sequenceDiagram
    participant Script as query_tpot_es.py
    participant ES as Elasticsearch
    participant Disk as Output Files
    
    Script->>ES: Query logs with 'input' field
    Note over Script,ES: Time range filter<br/>Honeypot type filter
    ES-->>Script: Raw log entries
    
    Script->>Script: Group by session ID
    Script->>Script: Sort commands chronologically
    Script->>Script: Extract GeoIP data
    
    Script->>Disk: sessions.json
    Script->>Disk: sessions_for_llm.txt
```

**Elasticsearch Query:**
```json
{
  "query": {
    "bool": {
      "must": [
        { "exists": { "field": "input" } },
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ],
      "must_not": [
        { "terms": { "type.keyword": ["Fatt", "Suricata", "P0f"] } }
      ]
    }
  }
}
```

### 2. LLM Analysis (analyze_sessions.py)

```mermaid
sequenceDiagram
    participant Script as analyze_sessions.py
    participant LLM as LM Studio API
    participant Disk as Output Files
    
    Script->>Script: Load sessions.json
    Script->>Script: Filter by min_commands
    
    loop For each session
        Script->>Script: Build analysis prompt
        Script->>LLM: POST /v1/chat/completions
        LLM-->>Script: Analysis response
        Script->>Script: Parse and store result
    end
    
    Script->>Disk: analysis_results.json
    Script->>Script: Generate reports
    Script->>Disk: analysis_report.md
    Script->>Disk: analysis_report_summary.md
```

**LLM Prompt Structure:**
```
System: You are a cybersecurity analyst...

User: Analyze the following honeypot session...

SESSION INFORMATION:
- Session ID: abc123
- Honeypot Type: Cowrie
- Attacker IP: 1.2.3.4
- Commands: [list of commands]

Please provide analysis covering:
1. Attack Type
2. Objective
3. Techniques
4. IOCs
5. Threat Level
6. Summary
```

### 3. Parallel Processing

```mermaid
flowchart TB
    subgraph Input["Session Queue"]
        S1["Session 1"]
        S2["Session 2"]
        S3["Session 3"]
        S4["Session 4"]
        SN["Session N..."]
    end
    
    subgraph Workers["Thread Pool (--workers 4)"]
        W1["Worker 1"]
        W2["Worker 2"]
        W3["Worker 3"]
        W4["Worker 4"]
    end
    
    subgraph LLM["LM Studio"]
        API["API Endpoint"]
    end
    
    subgraph Output["Results"]
        R1["Result 1"]
        R2["Result 2"]
        RN["Result N..."]
    end
    
    S1 --> W1
    S2 --> W2
    S3 --> W3
    S4 --> W4
    
    W1 <--> API
    W2 <--> API
    W3 <--> API
    W4 <--> API
    
    W1 --> R1
    W2 --> R2
    W3 --> RN
    W4 --> RN
```

## File Structure

```
tpot-honeypot-analyzer/
│
├── run_analysis.py          # Orchestration entry point
│   └── Calls: query_tpot_es.py → analyze_sessions.py
│
├── query_tpot_es.py          # Elasticsearch data extraction
│   ├── Input: Elasticsearch query
│   └── Output: sessions.json, sessions_for_llm.txt
│
├── analyze_sessions.py       # LLM analysis engine
│   ├── Input: sessions.json
│   └── Output: analysis_results.json, *.md reports
│
├── config.py                 # Configuration loader
│   └── Loads: config.yml, .env, environment variables
│
├── explore_tpot_es.py        # Utility for ES exploration
│
├── config.yml                # User configuration (git-ignored)
├── config.example.yml        # Example configuration
├── requirements.txt          # Python dependencies
│
└── output/                   # Analysis results (git-ignored)
    ├── 20251216_162229/      # Timestamped run
    │   ├── sessions.json
    │   ├── sessions_for_llm.txt
    │   ├── analysis_results.json
    │   ├── analysis_report.md
    │   └── analysis_report_summary.md
    └── latest -> 20251216_162229
```

## Configuration Flow

```mermaid
flowchart TB
    subgraph Sources["Configuration Sources"]
        Defaults["Default Values"]
        YAML["config.yml"]
        ENV["Environment Variables"]
        CLI["Command-line Args"]
    end
    
    subgraph Loader["config.py"]
        Load["Load & Merge"]
        Config["Config Object"]
    end
    
    subgraph Scripts["Scripts"]
        Run["run_analysis.py"]
        Query["query_tpot_es.py"]
        Analyze["analyze_sessions.py"]
    end
    
    Defaults -->|"Lowest priority"| Load
    YAML -->|"Override"| Load
    ENV -->|"Override"| Load
    CLI -->|"Highest priority"| Load
    
    Load --> Config
    
    Config --> Run
    Config --> Query
    Config --> Analyze
```

## Deployment Options

### Option 1: Same Machine as T-Pot

```mermaid
flowchart LR
    subgraph Server["Single Server"]
        TPot["T-Pot"]
        ES["Elasticsearch"]
        Analyzer["Analyzer"]
        LLM["LM Studio"]
    end
    
    Analyzer -->|"localhost:64298"| ES
    Analyzer -->|"localhost:1234"| LLM
```

**Pros:** Simple setup, no network configuration
**Cons:** Resource competition, LLM needs GPU

### Option 2: Separate Analysis Server

```mermaid
flowchart LR
    subgraph TPotServer["T-Pot Server"]
        TPot["T-Pot"]
        ES["Elasticsearch"]
    end
    
    subgraph AnalysisServer["Analysis Server"]
        Analyzer["Analyzer"]
        LLM["LM Studio"]
    end
    
    Analyzer -->|"Network"| ES
    Analyzer -->|"localhost"| LLM
```

**Pros:** Isolated resources, dedicated GPU for LLM
**Cons:** Network latency, firewall configuration

### Option 3: Distributed

```mermaid
flowchart LR
    subgraph TPotServer["T-Pot Server"]
        TPot["T-Pot"]
        ES["Elasticsearch"]
    end
    
    subgraph AnalysisServer["Analysis Server"]
        Analyzer["Analyzer"]
    end
    
    subgraph GPUServer["GPU Server"]
        LLM["LM Studio"]
    end
    
    Analyzer -->|"Network"| ES
    Analyzer -->|"Network"| LLM
```

**Pros:** Maximum flexibility, scalable
**Cons:** Complex setup, multiple network hops

## Security Considerations

```mermaid
flowchart TB
    subgraph Security["Security Boundaries"]
        subgraph DMZ["DMZ / Honeypot Network"]
            TPot["T-Pot"]
        end
        
        subgraph Internal["Internal Network"]
            ES["Elasticsearch\n(Restricted Access)"]
            Analyzer["Analyzer"]
            LLM["LM Studio"]
        end
    end
    
    TPot -->|"Logs"| ES
    Analyzer -->|"Query"| ES
    Analyzer -->|"Analysis"| LLM
```

**Recommendations:**

1. **Elasticsearch Access**
   - Bind to internal interface only
   - Use firewall rules to restrict access
   - Consider authentication for production

2. **LLM Server**
   - Run locally when possible
   - Never expose to internet
   - Use API keys if remote

3. **Output Data**
   - Contains attacker commands and IOCs
   - Store securely
   - Share IOCs responsibly

## Scaling

### Horizontal Scaling (More Sessions)

```mermaid
flowchart TB
    subgraph Parallel["Parallel Processing"]
        Sessions["Sessions"]
        
        subgraph Workers["Worker Pool"]
            W1["Worker 1"]
            W2["Worker 2"]
            W3["Worker 3"]
            W4["Worker 4"]
        end
        
        LLM["LM Studio"]
    end
    
    Sessions --> W1
    Sessions --> W2
    Sessions --> W3
    Sessions --> W4
    
    W1 --> LLM
    W2 --> LLM
    W3 --> LLM
    W4 --> LLM
```

Use `--workers N` to parallelize LLM calls:
```bash
python run_analysis.py --workers 8
```

### Vertical Scaling (Faster LLM)

| Approach | Benefit |
|----------|---------|
| Larger GPU | Faster inference |
| Quantized models | Lower memory, faster |
| Smaller models | Trade quality for speed |
| Dedicated LLM server | No resource contention |
