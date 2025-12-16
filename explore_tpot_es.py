#!/usr/bin/env python3
"""
explore_tpot_es.py - Exploration script for T-Pot Elasticsearch data

Useful for testing your connection and understanding your data structure.
- Lists all unique honeypot types
- Finds logs with 'input' field (shell commands)
- Shows sample data for analysis planning

Usage:
    python explore_tpot_es.py
"""

from elasticsearch import Elasticsearch
import json

from config import (
    ES_HOST, ES_PORT, ES_INDEX_PATTERN,
    get_es_client_config
)


def get_es_client():
    """Create Elasticsearch client connection."""
    config = get_es_client_config()
    es = Elasticsearch(**config)
    
    if es.ping():
        print(f"✓ Connected to Elasticsearch at {ES_HOST}:{ES_PORT}")
    else:
        print(f"✗ Failed to connect to Elasticsearch")
        exit(1)
    return es


def get_unique_types(es):
    """Get all unique values in the 'type' field using aggregation."""
    print("\nQuerying unique honeypot types...")
    
    query = {
        "size": 0,
        "aggs": {
            "honeypot_types": {
                "terms": {
                    "field": "type.keyword",
                    "size": 100
                }
            }
        }
    }
    
    response = es.search(index=ES_INDEX_PATTERN, body=query)
    buckets = response['aggregations']['honeypot_types']['buckets']
    
    print(f"\n{'='*50}")
    print("HONEYPOT TYPES FOUND:")
    print(f"{'='*50}")
    print(f"{'Type':<30} {'Doc Count':>15}")
    print(f"{'-'*30} {'-'*15}")
    
    for bucket in buckets:
        print(f"{bucket['key']:<30} {bucket['doc_count']:>15,}")
    
    print(f"{'='*50}")
    
    # Save to file
    output_file = "honeypot_types.json"
    with open(output_file, 'w') as f:
        json.dump(buckets, f, indent=2)
    print(f"\n✓ Saved types to {output_file}")
    
    return buckets


def get_logs_with_input(es, num_docs=100):
    """Get logs that have the 'input' field (shell commands)."""
    print(f"\nSearching for logs with 'input' field...")
    
    query = {
        "query": {
            "exists": {
                "field": "input"
            }
        },
        "size": num_docs,
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ]
    }
    
    response = es.search(index=ES_INDEX_PATTERN, body=query)
    hits = response['hits']['hits']
    total = response['hits']['total']['value']
    
    print(f"✓ Found {total} total logs with 'input' field")
    print(f"✓ Retrieved {len(hits)} samples")
    
    # Save to file
    output_file = "logs_with_input.json"
    with open(output_file, 'w') as f:
        json.dump(hits, f, indent=2, default=str)
    print(f"✓ Saved to {output_file}")
    
    # Show preview
    if hits:
        print(f"\n{'='*50}")
        print("SAMPLE LOGS WITH INPUT FIELD:")
        print(f"{'='*50}")
        
        # Group by type
        by_type = {}
        for hit in hits:
            src = hit['_source']
            t = src.get('type', 'unknown')
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(hit)
        
        print(f"\nTypes with 'input' field: {list(by_type.keys())}")
        
        for htype, type_hits in by_type.items():
            print(f"\n--- {htype} (showing up to 3) ---")
            for hit in type_hits[:3]:
                src = hit['_source']
                print(f"  Timestamp: {src.get('@timestamp', 'N/A')}")
                print(f"  Session: {src.get('session', 'N/A')}")
                input_cmd = src.get('input', 'N/A')
                if len(input_cmd) > 80:
                    input_cmd = input_cmd[:80] + "..."
                print(f"  Input: {input_cmd}")
                print(f"  src_ip: {src.get('src_ip', 'N/A')}")
                print()
    else:
        print("\n⚠ No logs with 'input' field found!")
    
    return hits


def get_input_types_breakdown(es):
    """Get breakdown of which honeypot types have 'input' field."""
    print("\nBreaking down 'input' field by honeypot type...")
    
    query = {
        "size": 0,
        "query": {
            "exists": {
                "field": "input"
            }
        },
        "aggs": {
            "types_with_input": {
                "terms": {
                    "field": "type.keyword",
                    "size": 50
                }
            }
        }
    }
    
    response = es.search(index=ES_INDEX_PATTERN, body=query)
    buckets = response['aggregations']['types_with_input']['buckets']
    
    print(f"\n{'='*50}")
    print("HONEYPOT TYPES WITH 'INPUT' FIELD:")
    print(f"{'='*50}")
    print(f"{'Type':<30} {'Doc Count':>15}")
    print(f"{'-'*30} {'-'*15}")
    
    for bucket in buckets:
        print(f"{bucket['key']:<30} {bucket['doc_count']:>15,}")
    
    print(f"{'='*50}")
    
    return buckets


def main():
    print("T-Pot Elasticsearch Explorer")
    print("="*50)
    
    # Connect
    es = get_es_client()
    
    # Get cluster info
    info = es.info()
    print(f"Cluster: {info['cluster_name']}")
    print(f"ES Version: {info['version']['number']}")
    
    # Get unique types
    get_unique_types(es)
    
    # Get breakdown of types with input
    get_input_types_breakdown(es)
    
    # Get sample logs with input
    get_logs_with_input(es, num_docs=100)
    
    print("\n✓ Exploration complete!")


if __name__ == "__main__":
    main()
