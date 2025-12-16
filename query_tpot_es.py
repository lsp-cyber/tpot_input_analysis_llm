#!/usr/bin/env python3
"""
query_tpot_es.py - Query T-Pot Elasticsearch for shell command logs

Pulls logs with 'input' field (shell commands captured by honeypots),
groups them by session, and outputs structured data for LLM analysis.

Configuration is loaded from config.yml and .env files.
See config.py for details.

Usage:
    python query_tpot_es.py
    python query_tpot_es.py --hours 12
    python query_tpot_es.py --days 7
    python query_tpot_es.py --hours 24 --output sessions.json
"""

import argparse
import json
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch
from collections import defaultdict

from config import config

# Elasticsearch has a default max_result_window of 10,000
# We use scroll API to retrieve more than that
ES_SCROLL_SIZE = 10000
ES_SCROLL_TIMEOUT = "5m"


def get_es_client():
    """Create Elasticsearch client connection."""
    es = Elasticsearch(
        [f"http://{config.elasticsearch.host}:{config.elasticsearch.port}"],
        request_timeout=config.elasticsearch.timeout
    )
    if not es.ping():
        raise ConnectionError(
            f"Failed to connect to Elasticsearch at "
            f"{config.elasticsearch.host}:{config.elasticsearch.port}"
        )
    return es


def query_input_logs(es, hours=12, max_results=None):
    """
    Query Elasticsearch for logs with 'input' field within the time range.
    Uses scroll API to handle large result sets.
    
    Args:
        es: Elasticsearch client
        hours: Number of hours to look back
        max_results: Maximum number of results to return (None = no limit)
        
    Returns:
        List of log documents
    """
    # Calculate time range
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=hours)
    
    print(f"Querying logs from {start_time.isoformat()} to {now.isoformat()}")
    print(f"Looking back {hours} hours ({hours/24:.1f} days)...")
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "input"}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": now.isoformat()
                            }
                        }
                    }
                ],
                "must_not": [
                    {"terms": {"type.keyword": config.analysis.exclude_types}}
                ]
            }
        },
        "sort": [
            {"@timestamp": {"order": "asc"}}
        ],
        "_source": [
            "session", "input", "src_ip", "type", "sensor",
            "t-pot_hostname", "@timestamp", "timestamp",
            "eventid", "geoip", "geoip_ext", "message"
        ]
    }
    
    # First, get the total count
    count_response = es.count(index=config.elasticsearch.index_pattern, body={"query": query["query"]})
    total_available = count_response['count']
    print(f"✓ Found {total_available:,} total logs with 'input' field in time range")
    
    if total_available == 0:
        return []
    
    # Determine how many to retrieve
    if max_results is None or max_results > total_available:
        target_count = total_available
    else:
        target_count = max_results
    
    # Use scroll API for large result sets
    all_hits = []
    
    if target_count <= ES_SCROLL_SIZE:
        # Small result set - single query is fine
        query["size"] = target_count
        response = es.search(index=config.elasticsearch.index_pattern, body=query)
        all_hits = [hit['_source'] for hit in response['hits']['hits']]
    else:
        # Large result set - use scroll API
        print(f"  Using scroll API to retrieve {target_count:,} logs in batches of {ES_SCROLL_SIZE:,}...")
        
        query["size"] = ES_SCROLL_SIZE
        response = es.search(
            index=config.elasticsearch.index_pattern,
            body=query,
            scroll=ES_SCROLL_TIMEOUT
        )
        
        scroll_id = response['_scroll_id']
        hits = response['hits']['hits']
        all_hits.extend([hit['_source'] for hit in hits])
        
        batch_num = 1
        while len(hits) > 0 and len(all_hits) < target_count:
            batch_num += 1
            print(f"    Batch {batch_num}: Retrieved {len(all_hits):,} / {target_count:,} logs...", end='\r')
            
            response = es.scroll(scroll_id=scroll_id, scroll=ES_SCROLL_TIMEOUT)
            scroll_id = response['_scroll_id']
            hits = response['hits']['hits']
            all_hits.extend([hit['_source'] for hit in hits])
        
        print()  # New line after progress
        
        # Clear scroll context
        try:
            es.clear_scroll(scroll_id=scroll_id)
        except Exception:
            pass  # Ignore errors clearing scroll
        
        # Trim to max_results if needed
        if max_results and len(all_hits) > max_results:
            all_hits = all_hits[:max_results]
    
    print(f"✓ Retrieved {len(all_hits):,} logs")
    
    return all_hits


def aggregate_by_session(logs):
    """
    Group logs by session ID and sort commands chronologically.
    
    Args:
        logs: List of log documents
        
    Returns:
        Dictionary of sessions with metadata and ordered commands
    """
    sessions = defaultdict(lambda: {
        "commands": [],
        "src_ip": None,
        "type": None,
        "sensor": None,
        "t-pot_hostname": None,
        "geoip": None,
        "start_time": None,
        "end_time": None
    })
    
    for log in logs:
        sess_id = log.get('session', 'unknown')
        session = sessions[sess_id]
        
        # Add command with timestamp
        session["commands"].append({
            "timestamp": log.get('@timestamp'),
            "input": log.get('input'),
            "eventid": log.get('eventid')
        })
        
        # Set session metadata (from first log encountered)
        if session["src_ip"] is None:
            session["src_ip"] = log.get('src_ip')
            session["type"] = log.get('type')
            session["sensor"] = log.get('sensor')
            session["t-pot_hostname"] = log.get('t-pot_hostname')
            session["geoip"] = log.get('geoip') or log.get('geoip_ext')
    
    # Sort commands within each session and calculate time range
    for sess_id, session in sessions.items():
        session["commands"].sort(key=lambda x: x["timestamp"] or "")
        
        if session["commands"]:
            session["start_time"] = session["commands"][0]["timestamp"]
            session["end_time"] = session["commands"][-1]["timestamp"]
            session["command_count"] = len(session["commands"])
    
    return dict(sessions)


def format_session_for_llm(session_id, session_data):
    """
    Format a session's data for LLM analysis.
    
    Args:
        session_id: The session identifier
        session_data: Session metadata and commands
        
    Returns:
        Formatted string for LLM prompt
    """
    lines = [
        f"Session ID: {session_id}",
        f"Honeypot Type: {session_data['type']}",
        f"Attacker IP: {session_data['src_ip']}",
        f"T-Pot Host: {session_data['t-pot_hostname']}",
        f"Time Range: {session_data['start_time']} to {session_data['end_time']}",
        f"Command Count: {session_data['command_count']}",
        "",
        "Commands executed (in order):",
        "-" * 40
    ]
    
    for i, cmd in enumerate(session_data["commands"], 1):
        lines.append(f"{i}. {cmd['input']}")
    
    return "\n".join(lines)


def print_summary(sessions):
    """Print a summary of the aggregated sessions."""
    print(f"\n{'='*60}")
    print("SESSION SUMMARY")
    print(f"{'='*60}")
    print(f"Total sessions: {len(sessions)}")
    
    # Group by honeypot type
    by_type = defaultdict(int)
    for sess in sessions.values():
        by_type[sess['type']] += 1
    
    print("\nSessions by honeypot type:")
    for htype, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {htype}: {count}")
    
    # Command count distribution
    cmd_counts = [s['command_count'] for s in sessions.values()]
    if cmd_counts:
        print(f"\nCommands per session:")
        print(f"  Min: {min(cmd_counts)}")
        print(f"  Max: {max(cmd_counts)}")
        print(f"  Avg: {sum(cmd_counts) / len(cmd_counts):.1f}")
    
    # Show top 5 sessions by command count
    print(f"\nTop 5 sessions by command count:")
    sorted_sessions = sorted(sessions.items(), key=lambda x: -x[1]['command_count'])
    for sess_id, sess in sorted_sessions[:5]:
        print(f"  {sess_id}: {sess['command_count']} commands from {sess['src_ip']} ({sess['type']})")
    
    print(f"{'='*60}")


def main():
    # Build help text with config values
    hours_help = f"Number of hours to look back (default from config: {config.analysis.lookback_hours or 'not set'})"
    days_help = f"Number of days to look back (default from config: {config.analysis.lookback_days or 'not set'})"
    
    parser = argparse.ArgumentParser(
        description="Query T-Pot Elasticsearch for shell command logs"
    )
    parser.add_argument(
        "--hours", 
        type=int, 
        default=None,
        help=hours_help
    )
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help=days_help
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=None,
        help="Maximum number of log entries to retrieve (default: no limit)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="sessions.json",
        help="Output file for session data (default: sessions.json)"
    )
    parser.add_argument(
        "--llm-output",
        type=str,
        default="sessions_for_llm.txt",
        help="Output file with formatted text for LLM (default: sessions_for_llm.txt)"
    )
    
    args = parser.parse_args()
    
    # Determine lookback hours from args or config
    if args.hours is not None:
        lookback_hours = args.hours
    elif args.days is not None:
        lookback_hours = args.days * 24
    else:
        lookback_hours = config.analysis.total_hours
    
    print("T-Pot Input Log Query Tool")
    print("="*60)
    print(f"Elasticsearch: {config.elasticsearch.host}:{config.elasticsearch.port}")
    print(f"Lookback: {lookback_hours} hours ({lookback_hours/24:.1f} days)")
    print("="*60)
    
    # Connect to Elasticsearch
    print(f"\nConnecting to {config.elasticsearch.host}:{config.elasticsearch.port}...")
    es = get_es_client()
    print("✓ Connected")
    
    # Query logs
    logs = query_input_logs(es, hours=lookback_hours, max_results=args.max_results)
    
    if not logs:
        print("\n⚠ No logs found in the specified time range")
        return
    
    # Aggregate by session
    print("\nAggregating logs by session...")
    sessions = aggregate_by_session(logs)
    print(f"✓ Found {len(sessions)} unique sessions")
    
    # Print summary
    print_summary(sessions)
    
    # Save JSON output
    with open(args.output, 'w') as f:
        json.dump(sessions, f, indent=2, default=str)
    print(f"\n✓ Saved session data to {args.output}")
    
    # Save LLM-formatted output
    with open(args.llm_output, 'w') as f:
        for sess_id, sess_data in sessions.items():
            f.write(format_session_for_llm(sess_id, sess_data))
            f.write("\n\n" + "="*60 + "\n\n")
    print(f"✓ Saved LLM-formatted data to {args.llm_output}")


if __name__ == "__main__":
    main()
