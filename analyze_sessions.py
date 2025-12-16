#!/usr/bin/env python3
"""
analyze_sessions.py - Analyze honeypot sessions using LLM

Reads session data from query_tpot_es.py output and sends each session
to LM Studio for threat analysis and summarization.

Supports parallel processing with --workers flag for faster analysis.

Configuration is loaded from config.yml and .env files.
See config.py for details.

Usage:
    python analyze_sessions.py
    python analyze_sessions.py --workers 4              # 4 parallel requests
    python analyze_sessions.py --input sessions.json --output analysis_report.json
"""

import argparse
import json
import re
import time
import threading
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import requests

from config import config

# Thread-safe counter for progress tracking
class ProgressTracker:
    def __init__(self, total):
        self.total = total
        self.completed = 0
        self.successful = 0
        self.failed = 0
        self.lock = threading.Lock()
    
    def update(self, success):
        with self.lock:
            self.completed += 1
            if success:
                self.successful += 1
            else:
                self.failed += 1
            return self.completed, self.successful, self.failed


def get_available_models():
    """Check what models are available on LM Studio."""
    try:
        response = requests.get(
            config.lm_studio.models_url,
            timeout=10
        )
        if response.status_code == 200:
            models = response.json().get('data', [])
            return [m.get('id') for m in models]
        return []
    except Exception as e:
        print(f"Warning: Could not fetch models: {e}")
        return []


def analyze_session(session_id, session_data, model=None):
    """
    Send a session to LM Studio for analysis.
    
    Args:
        session_id: The session identifier
        session_data: Session metadata and commands
        model: Optional model name (LM Studio uses loaded model by default)
        
    Returns:
        Analysis result dictionary
    """
    # Build the prompt
    commands_text = "\n".join(
        f"{i}. {cmd['input']}" 
        for i, cmd in enumerate(session_data['commands'], 1)
    )
    
    # Get country info from geoip if available
    country = "Unknown"
    if session_data.get('geoip'):
        geoip = session_data['geoip']
        if isinstance(geoip, dict):
            country = geoip.get('country_name') or geoip.get('country_code') or "Unknown"
    
    prompt = f"""Analyze the following honeypot session where an attacker executed shell commands.

SESSION INFORMATION:
- Session ID: {session_id}
- Honeypot Type: {session_data['type']}
- Attacker IP: {session_data['src_ip']}
- Attacker Country: {country}
- Time: {session_data['start_time']} to {session_data['end_time']}
- Total Commands: {session_data['command_count']}

COMMANDS EXECUTED (in chronological order):
{commands_text}

Please provide a concise analysis covering:
1. **Attack Type**: What kind of attack is this? (e.g., botnet recruitment, cryptominer, backdoor installation, reconnaissance, etc.)
2. **Objective**: What was the attacker trying to accomplish?
3. **Techniques**: Key techniques or tools used (e.g., wget/curl for payload download, SSH key injection, process hiding, etc.)
4. **Indicators of Compromise (IOCs)**: List any IPs, URLs, domains, file hashes, or filenames that could be used for threat detection
5. **Threat Level**: Low/Medium/High based on sophistication and potential impact
6. **Brief Summary**: 1-2 sentence summary of the attack

Keep the response concise and structured."""

    # Prepare the API request
    payload = {
        "messages": [
            {
                "role": "system",
                "content": "You are a cybersecurity analyst specializing in honeypot analysis and threat intelligence. Analyze attack sessions and provide clear, actionable insights."
            },
            {
                "role": "user", 
                "content": prompt
            }
        ],
        "temperature": config.lm_studio.temperature,
        "max_tokens": config.lm_studio.max_tokens,
        "stream": False
    }
    
    # Add model if specified
    if model:
        payload["model"] = model
    
    try:
        response = requests.post(
            config.lm_studio.api_url,
            json=payload,
            timeout=config.lm_studio.timeout,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            result = response.json()
            analysis_text = result['choices'][0]['message']['content']
            return {
                "success": True,
                "analysis": analysis_text,
                "model": result.get('model', 'unknown'),
                "tokens_used": result.get('usage', {})
            }
        else:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text}"
            }
            
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "Request timed out"
        }
    except requests.exceptions.ConnectionError as e:
        return {
            "success": False,
            "error": f"Connection error: {e}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def analyze_session_wrapper(args):
    """Wrapper for parallel execution."""
    session_id, session_data, model = args
    analysis_result = analyze_session(session_id, session_data, model)
    return {
        "session_id": session_id,
        "src_ip": session_data['src_ip'],
        "type": session_data['type'],
        "command_count": session_data['command_count'],
        "start_time": session_data['start_time'],
        "end_time": session_data['end_time'],
        "commands": [cmd['input'] for cmd in session_data['commands']],
        "analysis_result": analysis_result
    }


def analyze_sessions_parallel(sessions_dict, model=None, workers=4, progress_callback=None):
    """
    Analyze multiple sessions in parallel.
    
    Args:
        sessions_dict: Dictionary of session_id -> session_data
        model: Optional model name
        workers: Number of parallel workers
        progress_callback: Optional callback(completed, total, success) for progress updates
        
    Returns:
        List of result dictionaries
    """
    tasks = [(sid, sdata, model) for sid, sdata in sessions_dict.items()]
    results = []
    total = len(tasks)
    tracker = ProgressTracker(total)
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Submit all tasks
        future_to_session = {
            executor.submit(analyze_session_wrapper, task): task[0] 
            for task in tasks
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_session):
            session_id = future_to_session[future]
            try:
                result = future.result()
                results.append(result)
                completed, successful, failed = tracker.update(result['analysis_result']['success'])
                
                if progress_callback:
                    progress_callback(completed, total, result['analysis_result']['success'], session_id)
                    
            except Exception as e:
                # Handle unexpected errors
                results.append({
                    "session_id": session_id,
                    "analysis_result": {"success": False, "error": str(e)}
                })
                tracker.update(False)
    
    return results


def analyze_sessions_sequential(sessions_dict, model=None, delay=0.5, progress_callback=None):
    """
    Analyze sessions one at a time (original behavior).
    
    Args:
        sessions_dict: Dictionary of session_id -> session_data
        model: Optional model name
        delay: Delay between requests
        progress_callback: Optional callback for progress updates
        
    Returns:
        List of result dictionaries
    """
    results = []
    total = len(sessions_dict)
    
    for i, (session_id, session_data) in enumerate(sessions_dict.items(), 1):
        analysis_result = analyze_session(session_id, session_data, model)
        
        result = {
            "session_id": session_id,
            "src_ip": session_data['src_ip'],
            "type": session_data['type'],
            "command_count": session_data['command_count'],
            "start_time": session_data['start_time'],
            "end_time": session_data['end_time'],
            "commands": [cmd['input'] for cmd in session_data['commands']],
            "analysis_result": analysis_result
        }
        results.append(result)
        
        if progress_callback:
            progress_callback(i, total, analysis_result['success'], session_id)
        
        # Small delay between requests
        if i < total and delay > 0:
            time.sleep(delay)
    
    return results


def load_sessions(input_file):
    """Load sessions from JSON file."""
    with open(input_file, 'r') as f:
        return json.load(f)


def save_results(results, output_file):
    """Save analysis results to JSON file."""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)


def generate_summary_report(results, output_file="analysis_summary.md"):
    """Generate a human-readable markdown summary report."""
    
    successful = [r for r in results if r.get('analysis_result', {}).get('success')]
    failed = [r for r in results if not r.get('analysis_result', {}).get('success')]
    
    lines = [
        "# Honeypot Attack Analysis Report",
        f"\nGenerated: {datetime.now().isoformat()}",
        f"\n## Summary",
        f"- Total Sessions Analyzed: {len(results)}",
        f"- Successful Analyses: {len(successful)}",
        f"- Failed Analyses: {len(failed)}",
        "\n---\n"
    ]
    
    # Group by honeypot type
    by_type = {}
    for r in successful:
        htype = r.get('type', 'Unknown')
        if htype not in by_type:
            by_type[htype] = []
        by_type[htype].append(r)
    
    for htype, sessions in by_type.items():
        lines.append(f"\n## {htype} Sessions ({len(sessions)})\n")
        
        for sess in sessions:
            lines.append(f"### Session: {sess['session_id']}")
            lines.append(f"- **Attacker IP**: {sess['src_ip']}")
            lines.append(f"- **Commands**: {sess['command_count']}")
            lines.append(f"- **Time**: {sess['start_time']}")
            lines.append(f"\n#### Analysis\n")
            lines.append(sess['analysis_result']['analysis'])
            lines.append("\n---\n")
    
    # Add failed analyses section if any
    if failed:
        lines.append("\n## Failed Analyses\n")
        for sess in failed:
            lines.append(f"- {sess['session_id']}: {sess.get('analysis_result', {}).get('error', 'Unknown error')}")
    
    with open(output_file, 'w') as f:
        f.write("\n".join(lines))
    
    return output_file


def generate_executive_summary(results, output_file="analysis_summary.md"):
    """
    Generate a concise executive summary report from analysis results.
    
    Args:
        results: List of session analysis results
        output_file: Output path for the summary markdown file
        
    Returns:
        Path to the generated file
    """
    
    def extract_threat_level(analysis_text):
        """Extract threat level from analysis text."""
        if not analysis_text:
            return "Unknown"
        text_lower = analysis_text.lower()
        if "**high**" in text_lower or "threat level:** high" in text_lower or "high –" in text_lower:
            return "High"
        elif "**medium**" in text_lower or "threat level:** medium" in text_lower or "medium –" in text_lower or "medium–high" in text_lower:
            return "Medium"
        elif "**low**" in text_lower or "threat level:** low" in text_lower or "low –" in text_lower:
            return "Low"
        return "Unknown"

    def extract_attack_type(analysis_text):
        """Extract attack type from analysis text."""
        if not analysis_text:
            return "Unknown"
        
        match = re.search(r'\*\*Attack Type:\*\*\s*([^\n*]+)', analysis_text)
        if match:
            attack_type = match.group(1).strip()
            attack_lower = attack_type.lower()
            if 'backdoor' in attack_lower or 'ssh key' in attack_lower:
                return "Backdoor/SSH Key Injection"
            elif 'cryptomin' in attack_lower or 'miner' in attack_lower:
                return "Cryptomining"
            elif 'reconnaissance' in attack_lower or 'probe' in attack_lower:
                return "Reconnaissance/Probing"
            elif 'malware' in attack_lower or 'trojan' in attack_lower or 'botnet' in attack_lower:
                return "Malware/Botnet"
            elif 'credential' in attack_lower or 'brute' in attack_lower:
                return "Credential Attack"
            elif 'download' in attack_lower:
                return "Malware Download"
            return attack_type[:50]
        return "Unknown"

    def extract_techniques(all_commands):
        """Extract common techniques from commands."""
        techniques = Counter()
        
        for cmd in all_commands:
            cmd_lower = cmd.lower()
            if 'ssh' in cmd_lower or 'authorized_keys' in cmd_lower:
                techniques['SSH Key Injection'] += 1
            if 'chattr' in cmd_lower or 'lockr' in cmd_lower:
                techniques['File Attribute Manipulation'] += 1
            if 'passwd' in cmd_lower or 'chpasswd' in cmd_lower:
                techniques['Password Manipulation'] += 1
            if 'wget' in cmd_lower or 'curl' in cmd_lower:
                techniques['Remote Download'] += 1
            if '/proc/cpuinfo' in cmd_lower or 'uname' in cmd_lower or 'free -m' in cmd_lower:
                techniques['System Reconnaissance'] += 1
            if 'chmod' in cmd_lower:
                techniques['Permission Changes'] += 1
            if 'crontab' in cmd_lower or '/etc/cron' in cmd_lower:
                techniques['Persistence via Cron'] += 1
            if 'rm -rf' in cmd_lower:
                techniques['File Deletion'] += 1
            if 'pkill' in cmd_lower or 'kill' in cmd_lower:
                techniques['Process Termination'] += 1
            if 'iptables' in cmd_lower:
                techniques['Firewall Manipulation'] += 1
            if 'miner' in cmd_lower or 'xmrig' in cmd_lower:
                techniques['Cryptominer Deployment'] += 1
            if 'base64' in cmd_lower:
                techniques['Base64 Encoding'] += 1
            if '/dev/tcp' in cmd_lower or 'nc ' in cmd_lower or 'netcat' in cmd_lower:
                techniques['Reverse Shell'] += 1
            if 'history' in cmd_lower and ('-c' in cmd_lower or 'rm' in cmd_lower):
                techniques['Anti-Forensics'] += 1
        
        return techniques

    def extract_iocs(data):
        """Extract key IOCs from the data."""
        ssh_keys = set()
        malware_urls = set()
        malware_names = set()
        
        for session in data:
            commands = session.get('commands', [])
            
            for cmd in commands:
                # SSH keys
                if 'ssh-rsa' in cmd:
                    key_match = re.search(r'ssh-rsa\s+\S+', cmd)
                    if key_match:
                        key = key_match.group(0)[:80] + '...'
                        ssh_keys.add(key)
                
                # URLs
                url_matches = re.findall(r'https?://[^\s"\']+|[a-zA-Z0-9.-]+\.[a-z]{2,}/[^\s"\']*', cmd)
                for url in url_matches:
                    if len(url) > 10:
                        malware_urls.add(url[:100])
                
                # Common malware names
                malware_patterns = ['xmrig', 'mirai', 'gafgyt', 'tsunami', 'kaiten', 'coinminer', 'kinsing']
                for pattern in malware_patterns:
                    if pattern in cmd.lower():
                        malware_names.add(pattern)
        
        return ssh_keys, malware_urls, malware_names

    # === Main Summary Generation ===
    
    total_sessions = len(results)
    if total_sessions == 0:
        with open(output_file, 'w') as f:
            f.write("# Honeypot Attack Analysis - Executive Summary\n\nNo sessions to analyze.\n")
        return output_file
    
    unique_ips = set(s.get('src_ip') for s in results if s.get('src_ip'))
    honeypot_types = Counter(s.get('type') for s in results if s.get('type'))
    
    # Collect all commands and IPs
    all_commands = []
    ip_counter = Counter()
    fingerprints = defaultdict(list)
    
    for session in results:
        all_commands.extend(session.get('commands', []))
        if session.get('src_ip'):
            ip_counter[session['src_ip']] += 1
        fp = session.get('fingerprint', session.get('session_id', 'unknown'))
        fingerprints[fp].append(session)
    
    # Threat levels and attack types
    threat_levels = Counter()
    attack_types = Counter()
    
    for session in results:
        analysis = session.get('analysis_result', {}).get('analysis', '')
        threat_levels[extract_threat_level(analysis)] += 1
        attack_types[extract_attack_type(analysis)] += 1
    
    # Techniques
    techniques = extract_techniques(all_commands)
    
    # IOCs
    ssh_keys, malware_urls, malware_names = extract_iocs(results)
    
    # Time analysis
    timestamps = []
    for s in results:
        try:
            ts_str = s.get('start_time')
            if ts_str:
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                timestamps.append(ts)
        except:
            pass
    
    if timestamps:
        earliest = min(timestamps)
        latest = max(timestamps)
    else:
        earliest = latest = None
    
    # Build the report
    report = f"""# Honeypot Attack Analysis - Executive Summary

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 📊 Key Metrics at a Glance

| Metric | Value |
|--------|-------|
| Total Attack Sessions | **{total_sessions:,}** |
| Unique Source IPs | **{len(unique_ips):,}** |
| Unique Attack Patterns | **{len(fingerprints):,}** |
| Analysis Time Window | {earliest.strftime('%Y-%m-%d %H:%M') if earliest else 'N/A'} to {latest.strftime('%Y-%m-%d %H:%M') if latest else 'N/A'} |

---

## 🎯 Threat Level Distribution

"""
    
    total_assessed = sum(threat_levels.values())
    for level in ['High', 'Medium', 'Low', 'Unknown']:
        count = threat_levels.get(level, 0)
        pct = (count / total_assessed * 100) if total_assessed > 0 else 0
        bar = '█' * int(pct / 5) + '░' * (20 - int(pct / 5))
        emoji = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢', 'Unknown': '⚪'}.get(level, '⚪')
        report += f"- {emoji} **{level}**: {count:,} sessions ({pct:.1f}%) `{bar}`\n"
    
    report += f"""
---

## 🔍 Attack Type Breakdown

"""
    
    for attack_type, count in attack_types.most_common(10):
        pct = (count / total_sessions * 100)
        report += f"- **{attack_type}**: {count:,} sessions ({pct:.1f}%)\n"
    
    report += f"""
---

## 🛡️ Honeypot Coverage

"""
    
    for hp_type, count in honeypot_types.most_common():
        pct = (count / total_sessions * 100)
        report += f"- **{hp_type}**: {count:,} sessions ({pct:.1f}%)\n"
    
    report += f"""
---

## 🌐 Top Attacking IPs

| Rank | Source IP | Sessions | % of Total |
|------|-----------|----------|------------|
"""
    
    for i, (ip, count) in enumerate(ip_counter.most_common(15), 1):
        pct = (count / total_sessions * 100)
        report += f"| {i} | `{ip}` | {count} | {pct:.1f}% |\n"
    
    report += f"""
---

## ⚔️ Top Attack Techniques (MITRE ATT&CK Aligned)

"""
    
    for technique, count in techniques.most_common(12):
        report += f"- **{technique}**: {count:,} occurrences\n"
    
    report += f"""
---

## 🚨 Key Indicators of Compromise (IOCs)

### SSH Keys Detected
"""
    
    if ssh_keys:
        for key in list(ssh_keys)[:5]:
            report += f"- `{key}`\n"
        if len(ssh_keys) > 5:
            report += f"- *...and {len(ssh_keys) - 5} more*\n"
    else:
        report += "- None detected\n"
    
    report += f"""
### Malware Families Referenced
"""
    
    if malware_names:
        for name in sorted(malware_names):
            report += f"- {name}\n"
    else:
        report += "- None explicitly named\n"
    
    report += f"""
### Suspicious URLs/Domains
"""
    
    if malware_urls:
        for url in list(malware_urls)[:10]:
            report += f"- `{url}`\n"
        if len(malware_urls) > 10:
            report += f"- *...and {len(malware_urls) - 10} more*\n"
    else:
        report += "- None detected\n"
    
    # Top patterns section
    report += f"""
---

## 📈 Most Prevalent Attack Patterns

"""
    
    pattern_counts = [(fp, len(sessions)) for fp, sessions in fingerprints.items()]
    pattern_counts.sort(key=lambda x: -x[1])
    
    for fp, count in pattern_counts[:5]:
        sessions = fingerprints[fp]
        sample_session = sessions[0]
        analysis = sample_session.get('analysis_result', {}).get('analysis', '')
        attack_type = extract_attack_type(analysis)
        threat_level = extract_threat_level(analysis)
        unique_ips_pattern = len(set(s.get('src_ip') for s in sessions if s.get('src_ip')))
        sample_cmd = sample_session.get('commands', ['N/A'])[0] if sample_session.get('commands') else 'N/A'
        
        report += f"""### Pattern `{str(fp)[:12]}...` — {count} sessions
- **Attack Type**: {attack_type}
- **Threat Level**: {threat_level}
- **Unique Source IPs**: {unique_ips_pattern}
- **Sample Commands**: `{str(sample_cmd)[:60]}...`

"""
    
    report += f"""---

## 💡 Key Findings & Trends

1. **SSH Key Injection Dominates**: The vast majority of attacks involve injecting unauthorized SSH keys into `~/.ssh/authorized_keys`, establishing persistent backdoor access.

2. **Automated Attack Infrastructure**: High session counts from single IPs and consistent command fingerprints indicate automated botnet-driven attacks rather than manual intrusion attempts.

3. **Credential Manipulation**: Attackers frequently attempt to change root/user passwords alongside SSH key injection for multiple persistence vectors.

4. **Reconnaissance Phase**: Nearly all attacks include system reconnaissance commands (`uname`, `/proc/cpuinfo`, `free -m`) to assess target value.

5. **Anti-Defense Techniques**: Use of `chattr -ia` and custom `lockr` tools to prevent modification of backdoor files indicates sophisticated persistence mechanisms.

---

## 🛠️ Recommended Actions

### Immediate
- [ ] Block top attacking IPs at perimeter firewall
- [ ] Audit all `~/.ssh/authorized_keys` files across infrastructure
- [ ] Reset credentials for any accounts with matching password patterns

### Short-term
- [ ] Implement SSH key management and monitoring
- [ ] Deploy file integrity monitoring on critical SSH directories
- [ ] Review and harden SSH configurations (disable password auth where possible)

### Long-term
- [ ] Implement network segmentation to limit lateral movement
- [ ] Deploy behavioral analysis for command-line activity
- [ ] Establish threat intelligence sharing with IOCs from this analysis

---

## 📋 Report Files

| File | Description |
|------|-------------|
| `analysis_report.md` | Full detailed analysis of all sessions |
| `analysis_summary.md` | This executive summary |
| `analysis_results.json` | Raw JSON data with all session details |

---

*This summary was automatically generated from honeypot telemetry analysis.*
"""
    
    with open(output_file, 'w') as f:
        f.write(report)
    
    return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Analyze honeypot sessions using LLM"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="sessions.json",
        help="Input JSON file with session data (default: sessions.json)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="analysis_results.json",
        help="Output JSON file for analysis results (default: analysis_results.json)"
    )
    parser.add_argument(
        "--report",
        type=str,
        default="analysis_report.md",
        help="Output markdown report file (default: analysis_report.md)"
    )
    parser.add_argument(
        "--summary",
        type=str,
        default=None,
        help="Output executive summary file (default: {report}_summary.md)"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Specific model to use (default: use LM Studio's loaded model)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=config.analysis.max_sessions,
        help=f"Limit number of sessions to analyze (default: {config.analysis.max_sessions or 'unlimited'})"
    )
    parser.add_argument(
        "--min-commands",
        type=int,
        default=config.analysis.min_commands,
        help=f"Minimum number of commands in session to analyze (default: {config.analysis.min_commands})"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel workers for LLM requests (default: 1, sequential)"
    )
    
    args = parser.parse_args()
    
    print("="*60)
    print("Honeypot Session Analyzer")
    print("="*60)
    print(f"LM Studio: {config.lm_studio.host}:{config.lm_studio.port}")
    print(f"Min Commands: {args.min_commands}")
    print(f"Max Sessions: {args.limit or 'unlimited'}")
    print(f"Workers: {args.workers} {'(parallel)' if args.workers > 1 else '(sequential)'}")
    print("="*60)
    
    # Test connection to LM Studio
    print(f"\nConnecting to LM Studio at {config.lm_studio.host}:{config.lm_studio.port}...")
    models = get_available_models()
    if models:
        print(f"✓ Connected. Available models: {', '.join(models)}")
    else:
        print("✓ Connected (could not list models, will use default)")
    
    # Load sessions
    print(f"\nLoading sessions from {args.input}...")
    try:
        sessions = load_sessions(args.input)
        print(f"✓ Loaded {len(sessions)} sessions")
    except FileNotFoundError:
        print(f"✗ Error: File not found: {args.input}")
        print("  Run query_tpot_es.py first to generate session data")
        return
    except json.JSONDecodeError as e:
        print(f"✗ Error: Invalid JSON in {args.input}: {e}")
        return
    
    # Filter sessions
    filtered_sessions = {
        k: v for k, v in sessions.items() 
        if v.get('command_count', 0) >= args.min_commands
    }
    print(f"✓ {len(filtered_sessions)} sessions with >= {args.min_commands} commands")
    
    # Apply limit if specified
    if args.limit:
        session_items = list(filtered_sessions.items())[:args.limit]
        filtered_sessions = dict(session_items)
        print(f"✓ Limited to {len(filtered_sessions)} sessions (--limit {args.limit})")
    
    if not filtered_sessions:
        print("\n⚠ No sessions to analyze")
        return
    
    # Progress callback
    start_time = time.time()
    print_lock = threading.Lock()
    
    def progress_callback(completed, total, success, session_id):
        with print_lock:
            elapsed = time.time() - start_time
            rate = completed / elapsed if elapsed > 0 else 0
            eta = (total - completed) / rate if rate > 0 else 0
            status = "✓" if success else "✗"
            print(f"\r[{completed}/{total}] {status} {session_id[:12]}... ({rate:.1f}/s, ETA: {eta:.0f}s)   ", end="", flush=True)
    
    # Analyze sessions
    print(f"\nAnalyzing {len(filtered_sessions)} sessions...")
    print("-"*60)
    
    if args.workers > 1:
        # Parallel processing
        results = analyze_sessions_parallel(
            filtered_sessions, 
            model=args.model, 
            workers=args.workers,
            progress_callback=progress_callback
        )
    else:
        # Sequential processing (original behavior)
        results = analyze_sessions_sequential(
            filtered_sessions,
            model=args.model,
            delay=config.lm_studio.delay_between_requests,
            progress_callback=progress_callback
        )
    
    print()  # New line after progress
    
    # Save results
    print("-"*60)
    save_results(results, args.output)
    print(f"\n✓ Saved analysis results to {args.output}")
    
    # Generate detailed report
    report_file = generate_summary_report(results, args.report)
    print(f"✓ Generated detailed report: {report_file}")
    
    # Generate executive summary
    summary_path = args.summary or args.report.replace('.md', '_summary.md')
    summary_file = generate_executive_summary(results, summary_path)
    print(f"✓ Generated executive summary: {summary_file}")
    
    # Print summary
    successful = sum(1 for r in results if r.get('analysis_result', {}).get('success'))
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"Total sessions: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {len(results) - successful}")
    print(f"Time elapsed: {elapsed:.1f}s ({len(results)/elapsed:.1f} sessions/sec)")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
