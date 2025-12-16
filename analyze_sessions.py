#!/usr/bin/env python3
"""
analyze_sessions.py - Analyze honeypot sessions using LLM

Reads session data from query_tpot_es.py output and sends each session
to LM Studio (or any OpenAI-compatible API) for threat analysis.

Usage:
    python analyze_sessions.py
    python analyze_sessions.py --input sessions.json --output analysis_report.json
"""

import argparse
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path
import requests

from config import (
    LLM_HOST, LLM_PORT, LLM_API_URL, LLM_MODEL,
    REQUEST_TIMEOUT, DELAY_BETWEEN_REQUESTS, MAX_CONSECUTIVE_FAILURES,
    CACHE_FILE, get_llm_headers
)


def get_command_fingerprint(commands):
    """
    Generate a fingerprint hash for a sequence of commands.
    This allows us to identify identical attack patterns.
    
    Args:
        commands: List of command dicts with 'input' field
        
    Returns:
        SHA256 hash string (first 16 chars)
    """
    cmd_strings = [cmd.get('input', '') for cmd in commands]
    normalized = "\n".join(cmd_strings)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:16]


def load_cache(cache_file):
    """Load the analysis cache from disk."""
    cache_path = Path(cache_file)
    if cache_path.exists():
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load cache: {e}")
    return {}


def save_cache(cache, cache_file):
    """Save the analysis cache to disk."""
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        print(f"Warning: Could not save cache: {e}")


def get_cached_analysis(fingerprint, cache):
    """Get cached analysis for a command fingerprint."""
    if fingerprint in cache:
        entry = cache[fingerprint]
        return {
            "success": True,
            "analysis": entry['analysis'],
            "model": entry.get('model', 'cached'),
            "cached": True,
            "cache_hits": entry.get('hit_count', 0) + 1,
            "first_seen": entry.get('first_seen'),
            "example_session": entry.get('example_session')
        }
    return None


def cache_analysis(fingerprint, analysis_result, session_id, cache):
    """Cache an analysis result."""
    if analysis_result.get('success'):
        cache[fingerprint] = {
            'analysis': analysis_result['analysis'],
            'model': analysis_result.get('model', 'unknown'),
            'first_seen': datetime.now().isoformat(),
            'example_session': session_id,
            'hit_count': 0
        }


def increment_cache_hit(fingerprint, cache):
    """Increment the hit counter for a cached entry."""
    if fingerprint in cache:
        cache[fingerprint]['hit_count'] = cache[fingerprint].get('hit_count', 0) + 1


def get_available_models():
    """Check what models are available on the LLM server."""
    try:
        models_url = LLM_API_URL.replace('/chat/completions', '/models')
        response = requests.get(models_url, timeout=10, headers=get_llm_headers())
        if response.status_code == 200:
            models = response.json().get('data', [])
            return [m.get('id') for m in models]
        return []
    except Exception as e:
        print(f"Warning: Could not fetch models: {e}")
        return []


def test_model_loaded():
    """
    Test if the LLM server has a model loaded and ready.
    Returns (success, message) tuple.
    """
    try:
        payload = {
            "messages": [{"role": "user", "content": "test"}],
            "max_tokens": 5,
            "stream": False
        }
        if LLM_MODEL:
            payload["model"] = LLM_MODEL
        
        response = requests.post(
            LLM_API_URL,
            json=payload,
            timeout=30,
            headers=get_llm_headers()
        )
        
        if response.status_code == 200:
            result = response.json()
            model = result.get('model', 'unknown')
            return True, f"Model ready: {model}"
        else:
            error_data = response.json()
            error_msg = error_data.get('error', {}).get('message', response.text)
            return False, error_msg
            
    except requests.exceptions.ConnectionError:
        return False, f"Cannot connect to LLM server at {LLM_HOST}:{LLM_PORT}"
    except requests.exceptions.Timeout:
        return False, "Connection timed out"
    except Exception as e:
        return False, str(e)


def analyze_session(session_id, session_data, model=None):
    """
    Send a session to the LLM for analysis.
    
    Args:
        session_id: The session identifier
        session_data: Session metadata and commands
        model: Optional model name override
        
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
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 1000,
        "stream": False
    }
    
    # Use model from arg, config, or let server decide
    use_model = model or LLM_MODEL
    if use_model:
        payload["model"] = use_model
    
    try:
        response = requests.post(
            LLM_API_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            headers=get_llm_headers()
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
        return {"success": False, "error": "Request timed out"}
    except requests.exceptions.ConnectionError as e:
        return {"success": False, "error": f"Connection error: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


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
    
    unique_patterns = len(set(r.get('fingerprint', 'unknown') for r in results))
    
    lines = [
        "# Honeypot Attack Analysis Report",
        f"\nGenerated: {datetime.now().isoformat()}",
        f"\n## Summary",
        f"- Total Sessions Analyzed: {len(results)}",
        f"- Unique Attack Patterns: {unique_patterns}",
        f"- Successful Analyses: {len(successful)}",
        f"- Failed Analyses: {len(failed)}",
        "\n---\n"
    ]
    
    # Group by fingerprint to show unique patterns
    by_pattern = {}
    for r in successful:
        fp = r.get('fingerprint', 'unknown')
        if fp not in by_pattern:
            by_pattern[fp] = {
                'sessions': [],
                'analysis': r['analysis_result']['analysis'],
                'type': r.get('type'),
                'example_commands': r.get('commands', [])
            }
        by_pattern[fp]['sessions'].append(r)
    
    # Sort patterns by number of sessions (most common first)
    sorted_patterns = sorted(by_pattern.items(), key=lambda x: -len(x[1]['sessions']))
    
    lines.append(f"\n## Attack Patterns ({len(sorted_patterns)} unique)\n")
    
    for fp, pattern_data in sorted_patterns:
        session_count = len(pattern_data['sessions'])
        sessions = pattern_data['sessions']
        
        unique_ips = list(set(s['src_ip'] for s in sessions))
        
        lines.append(f"### Pattern: {fp[:12]}...")
        lines.append(f"- **Sessions**: {session_count}")
        lines.append(f"- **Honeypot Type**: {pattern_data['type']}")
        lines.append(f"- **Unique Source IPs**: {len(unique_ips)}")
        if len(unique_ips) <= 5:
            lines.append(f"- **Source IPs**: {', '.join(unique_ips)}")
        else:
            lines.append(f"- **Sample IPs**: {', '.join(unique_ips[:5])}... (+{len(unique_ips)-5} more)")
        
        lines.append(f"\n#### Analysis\n")
        lines.append(pattern_data['analysis'])
        
        lines.append(f"\n#### Sample Commands\n```")
        for cmd in pattern_data['example_commands'][:10]:
            lines.append(cmd[:100] + "..." if len(cmd) > 100 else cmd)
        if len(pattern_data['example_commands']) > 10:
            lines.append(f"... (+{len(pattern_data['example_commands'])-10} more)")
        lines.append("```")
        lines.append("\n---\n")
    
    if failed:
        lines.append("\n## Failed Analyses\n")
        for sess in failed:
            lines.append(f"- {sess['session_id']}: {sess.get('analysis_result', {}).get('error', 'Unknown error')}")
    
    with open(output_file, 'w') as f:
        f.write("\n".join(lines))
    
    return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Analyze honeypot sessions using LLM"
    )
    parser.add_argument(
        "--input", type=str, default="sessions.json",
        help="Input JSON file with session data (default: sessions.json)"
    )
    parser.add_argument(
        "--output", type=str, default="analysis_results.json",
        help="Output JSON file for analysis results (default: analysis_results.json)"
    )
    parser.add_argument(
        "--report", type=str, default="analysis_report.md",
        help="Output markdown report file (default: analysis_report.md)"
    )
    parser.add_argument(
        "--model", type=str, default=None,
        help="Specific model to use (default: use server's loaded model)"
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Limit number of sessions to analyze (for testing)"
    )
    parser.add_argument(
        "--min-commands", type=int, default=1,
        help="Minimum number of commands in session to analyze (default: 1)"
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Disable cache (always query LLM)"
    )
    parser.add_argument(
        "--clear-cache", action="store_true",
        help="Clear the cache before running"
    )
    parser.add_argument(
        "--cache-file", type=str, default=str(CACHE_FILE),
        help=f"Path to cache file (default: {CACHE_FILE})"
    )
    
    args = parser.parse_args()
    
    print("="*60)
    print("Honeypot Session Analyzer")
    print("="*60)
    
    # Load sessions first
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
    
    if args.limit:
        session_items = list(filtered_sessions.items())[:args.limit]
        filtered_sessions = dict(session_items)
        print(f"✓ Limited to {len(filtered_sessions)} sessions (--limit {args.limit})")
    
    if not filtered_sessions:
        print("\n⚠ No sessions to analyze")
        return
    
    # Handle cache
    cache_file = Path(args.cache_file)
    
    if args.clear_cache and cache_file.exists():
        cache_file.unlink()
        print(f"✓ Cleared cache file: {cache_file}")
    
    cache = {} if args.no_cache else load_cache(cache_file)
    if cache and not args.no_cache:
        print(f"✓ Loaded {len(cache)} cached analyses from {cache_file}")
    
    # Pre-calculate fingerprints and group sessions
    print("\nAnalyzing command patterns...")
    fingerprints = {}
    sessions_by_fingerprint = {}
    
    for session_id, session_data in filtered_sessions.items():
        fp = get_command_fingerprint(session_data['commands'])
        fingerprints[session_id] = fp
        
        if fp not in sessions_by_fingerprint:
            sessions_by_fingerprint[fp] = []
        sessions_by_fingerprint[fp].append(session_id)
    
    unique_patterns = len(sessions_by_fingerprint)
    total_sessions = len(filtered_sessions)
    
    print(f"✓ {total_sessions} sessions → {unique_patterns} unique command patterns")
    print(f"  Deduplication ratio: {total_sessions/unique_patterns:.1f}x")
    
    # Show pattern distribution
    pattern_sizes = {}
    for fp, sess_list in sessions_by_fingerprint.items():
        size = len(sess_list)
        pattern_sizes[size] = pattern_sizes.get(size, 0) + 1
    
    print(f"\n  Pattern frequency distribution:")
    for size in sorted(pattern_sizes.keys(), reverse=True)[:5]:
        count = pattern_sizes[size]
        if size > 1:
            print(f"    {count} pattern(s) seen in {size} sessions each")
    single_patterns = pattern_sizes.get(1, 0)
    if single_patterns:
        print(f"    {single_patterns} unique pattern(s) seen only once")
    
    # Check cache hits against unique patterns
    cached_patterns = sum(1 for fp in sessions_by_fingerprint.keys() if fp in cache)
    new_patterns = unique_patterns - cached_patterns
    
    if not args.no_cache:
        print(f"\n✓ Cache status:")
        print(f"    {cached_patterns}/{unique_patterns} patterns already cached ({100*cached_patterns/unique_patterns:.1f}%)")
        print(f"    {new_patterns} new patterns to analyze")
        
        if new_patterns == 0:
            print("\n✓ All patterns cached - skipping LLM server check")
    
    # Only check LLM server if we have new patterns
    if new_patterns > 0 or args.no_cache:
        print(f"\nConnecting to LLM server at {LLM_HOST}:{LLM_PORT}...")
        
        models = get_available_models()
        if models:
            print(f"✓ Server reachable. Available models: {', '.join(models)}")
        else:
            print("✓ Server reachable")
        
        print("Testing if model is loaded and ready...")
        model_ready, message = test_model_loaded()
        
        if not model_ready:
            print(f"✗ Model not ready: {message}")
            print("\n" + "="*60)
            print("ACTION REQUIRED:")
            print("="*60)
            print("Please load a model in your LLM server (e.g., LM Studio):")
            print("  1. Open LM Studio")
            print("  2. Go to the 'Developer' tab")
            print("  3. Load a model")
            print("  4. Wait for 'Server ready' status")
            print("  5. Re-run this script")
            if models:
                print(f"\nAvailable models: {', '.join(models)}")
            print("="*60)
            return
        
        print(f"✓ {message}")
    
    # Analyze unique patterns
    print(f"\nAnalyzing {unique_patterns} unique patterns...")
    print("-"*60)
    
    results = []
    consecutive_failures = 0
    stats = {"cached": 0, "analyzed": 0, "failed": 0}
    pattern_analyses = {}
    
    patterns_to_process = list(sessions_by_fingerprint.keys())
    
    for i, fingerprint in enumerate(patterns_to_process, 1):
        session_ids = sessions_by_fingerprint[fingerprint]
        representative_session_id = session_ids[0]
        session_data = filtered_sessions[representative_session_id]
        session_count = len(session_ids)
        
        print(f"[{i}/{unique_patterns}] Pattern {fingerprint[:8]}... ({session_count} sessions)...", end=" ", flush=True)
        
        # Check cache first
        if not args.no_cache:
            cached_result = get_cached_analysis(fingerprint, cache)
            if cached_result:
                print("✓ (cached)")
                increment_cache_hit(fingerprint, cache)
                pattern_analyses[fingerprint] = cached_result
                stats["cached"] += 1
                continue
        
        # Query LLM
        analysis_result = analyze_session(representative_session_id, session_data, model=args.model)
        
        if analysis_result['success']:
            print("✓ (analyzed)")
            consecutive_failures = 0
            stats["analyzed"] += 1
            
            if not args.no_cache:
                cache_analysis(fingerprint, analysis_result, representative_session_id, cache)
            
            pattern_analyses[fingerprint] = analysis_result
        else:
            error_msg = analysis_result.get('error', 'Unknown error')
            print(f"✗ ({error_msg[:40]}...)" if len(error_msg) > 40 else f"✗ ({error_msg})")
            consecutive_failures += 1
            stats["failed"] += 1
            pattern_analyses[fingerprint] = analysis_result
            
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                print(f"\n✗ Aborting: {MAX_CONSECUTIVE_FAILURES} consecutive failures")
                break
        
        if i < len(patterns_to_process) and consecutive_failures == 0:
            time.sleep(DELAY_BETWEEN_REQUESTS)
    
    # Build results for ALL sessions
    print(f"\nApplying analyses to all {total_sessions} sessions...")
    
    for session_id, session_data in filtered_sessions.items():
        fingerprint = fingerprints[session_id]
        analysis_result = pattern_analyses.get(fingerprint, {"success": False, "error": "Pattern not analyzed"})
        
        results.append({
            "session_id": session_id,
            "src_ip": session_data['src_ip'],
            "type": session_data['type'],
            "command_count": session_data['command_count'],
            "start_time": session_data['start_time'],
            "end_time": session_data['end_time'],
            "commands": [cmd['input'] for cmd in session_data['commands']],
            "fingerprint": fingerprint,
            "pattern_sessions": len(sessions_by_fingerprint[fingerprint]),
            "analysis_result": analysis_result
        })
    
    # Save cache
    if not args.no_cache:
        save_cache(cache, cache_file)
        print(f"✓ Saved {len(cache)} analyses to cache")
    
    # Save results
    print("-"*60)
    save_results(results, args.output)
    print(f"\n✓ Saved analysis results to {args.output}")
    
    # Generate report
    report_file = generate_summary_report(results, args.report)
    print(f"✓ Generated summary report: {report_file}")
    
    # Print summary
    print(f"\n{'='*60}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"Sessions processed: {len(results)}")
    print(f"Unique patterns: {unique_patterns}")
    print(f"  From cache: {stats['cached']}")
    print(f"  Newly analyzed: {stats['analyzed']}")
    print(f"  Failed: {stats['failed']}")
    print(f"\nLLM calls saved by deduplication: {total_sessions - unique_patterns}")
    if not args.no_cache:
        print(f"Cache now contains {len(cache)} unique attack patterns")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
