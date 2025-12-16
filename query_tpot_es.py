#!/usr/bin/env python3
"""
query_tpot_es.py - Query T-Pot Elasticsearch for shell command logs

Pulls logs with 'input' field (shell commands captured by honeypots),
groups them by session, and outputs structured data for LLM analysis.

Usage:
    python query_tpot_es.py --hours 12
    python query_tpot_es.py --hours 24 --output sessions.json
"""

import argparse
import json
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch
from collections import defaultdict

from config import (
    ES_HOST, ES_PORT, ES_INDEX_PATTERN, 
    EXCLUDE_TYPES, INPUT_TYPES,
    get_es_client_config
)


def get_es_client():
    """Create Elasticsearch client connection."""
    config = get_es_client_config()
    es = Elasticsearch(**config)
    
    if not es.ping():
        raise ConnectionError(f"Failed to connect to Elasticsearch at {ES_HOST}:{ES_PORT}")
    return es


def query_input_logs(es, hours=12, max_results=10000):
    """
    Query Elasticsearch for logs with 'input' field within the time range.
    
    Args:
        es: Elasticsearch client
        hours: Number of hours to look back
        max_results: Maximum number of results to return
        
    Returns:
        List of log documents
    """
    # Calculate time range
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=hours)
    
    print(f"Querying logs from {start_time.isoformat()} to {now.isoformat()}")
    print(f"Looking back {hours} hours...")
    
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
                    {"terms": {"type.keyword": EXCLUDE_TYPES}}
                ]
            }
        },
        "size": max_results,
        "sort": [
            {"@timestamp": {"order": "asc"}}
        ],
        "_source": [
            "session", "input", "src_ip", "type", "sensor",
            "t-pot_hostname", "@timestamp", "timestamp",
            "eventid", "geoip", "geoip_ext", "message"
        ]
    }
    
    response = es.search(index=ES_INDEX_PATTERN, body=query)
    hits = response['hits']['hits']
    total = response['hits']['total']['value']
    
    print(f"✓ Found {total} total logs with 'input' field in time range")
    print(f"✓ Retrieved {len(hits)} logs")
    
    return [hit['_source'] for hit in hits]


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
    parser = argparse.ArgumentParser(
        description="Query T-Pot Elasticsearch for shell command logs"
    )
    parser.add_argument(
        "--hours", 
        type=int, 
        default=12,
        help="Number of hours to look back (default: 12)"
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=10000,
        help="Maximum number of log entries to retrieve (default: 10000)"
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
    
    print("T-Pot Input Log Query Tool")
    print("="*60)
    
    # Connect to Elasticsearch
    print(f"Connecting to {ES_HOST}:{ES_PORT}...")
    es = get_es_client()
    print("✓ Connected")
    
    # Query logs
    logs = query_input_logs(es, hours=args.hours, max_results=args.max_results)
    
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
