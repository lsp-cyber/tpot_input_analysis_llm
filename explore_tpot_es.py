#!/usr/bin/env python3
"""
Exploration script for T-Pot Elasticsearch data
- Pulls 500 sample log entries
- Lists all unique honeypot types in the "type" field
- Finds and displays logs with "input" field (shell commands)

Configuration is loaded from config.yml and .env files.
See config.py for details.
"""

from elasticsearch import Elasticsearch
from datetime import datetime
import json

from config import config


def get_es_client():
    """Create Elasticsearch client connection."""
    es = Elasticsearch(
        [f"http://{config.elasticsearch.host}:{config.elasticsearch.port}"],
        request_timeout=config.elasticsearch.timeout
    )
    # Test connection
    if es.ping():
        print(f"✓ Connected to Elasticsearch at {config.elasticsearch.host}:{config.elasticsearch.port}")
    else:
        print(f"✗ Failed to connect to Elasticsearch")
        exit(1)
    return es


def pull_sample_logs(es, num_docs=500):
    """Pull sample log entries and save to file."""
    print(f"\nPulling {num_docs} sample log entries...")
    
    query = {
        "query": {
            "match_all": {}
        },
        "size": num_docs,
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ]
    }
    
    response = es.search(index=config.elasticsearch.index_pattern, body=query)
    hits = response['hits']['hits']
    
    print(f"✓ Retrieved {len(hits)} log entries")
    
    # Save to file
    output_file = "sample_logs.json"
    with open(output_file, 'w') as f:
        json.dump(hits, f, indent=2, default=str)
    print(f"✓ Saved to {output_file}")
    
    return hits


def get_unique_types(es):
    """Get all unique values in the 'type' field using aggregation."""
    print("\nQuerying unique honeypot types...")
    
    query = {
        "size": 0,  # We don't need actual documents
        "aggs": {
            "honeypot_types": {
                "terms": {
                    "field": "type.keyword",  # Use keyword subfield for aggregation
                    "size": 100  # Get up to 100 unique types
                }
            }
        }
    }
    
    response = es.search(index=config.elasticsearch.index_pattern, body=query)
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
    
    response = es.search(index=config.elasticsearch.index_pattern, body=query)
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
        
        # Group by type to show variety
        by_type = {}
        for hit in hits:
            src = hit['_source']
            t = src.get('type', 'unknown')
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(hit)
        
        print(f"\nTypes with 'input' field: {list(by_type.keys())}")
        
        # Show a few examples from each type
        for htype, type_hits in by_type.items():
            print(f"\n--- {htype} (showing up to 3) ---")
            for hit in type_hits[:3]:
                src = hit['_source']
                print(f"  Timestamp: {src.get('@timestamp', 'N/A')}")
                print(f"  Session: {src.get('session', 'N/A')}")
                print(f"  Input: {src.get('input', 'N/A')}")
                print(f"  src_ip: {src.get('src_ip', 'N/A')}")
                print(f"  Fields: {list(src.keys())}")
                print()
    else:
        print("\n⚠ No logs with 'input' field found in the index!")
    
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
    
    response = es.search(index=config.elasticsearch.index_pattern, body=query)
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


def preview_sample_fields(hits, num_preview=3):
    """Show a preview of the fields in sample documents."""
    print(f"\n{'='*50}")
    print(f"PREVIEW OF FIRST {num_preview} DOCUMENTS:")
    print(f"{'='*50}")
    
    for i, hit in enumerate(hits[:num_preview]):
        print(f"\n--- Document {i+1} ---")
        print(f"Index: {hit['_index']}")
        source = hit['_source']
        print(f"Type: {source.get('type', 'N/A')}")
        print(f"Timestamp: {source.get('@timestamp', 'N/A')}")
        print(f"Fields present: {list(source.keys())}")
        
        # Check if 'input' field exists
        if 'input' in source:
            print(f"INPUT FIELD: {source['input'][:100]}..." if len(str(source.get('input', ''))) > 100 else f"INPUT FIELD: {source.get('input')}")


def main():
    print("T-Pot Elasticsearch Explorer")
    print("="*50)
    print(f"Elasticsearch: {config.elasticsearch.host}:{config.elasticsearch.port}")
    print(f"Index Pattern: {config.elasticsearch.index_pattern}")
    print("="*50)
    
    # Connect
    es = get_es_client()
    
    # Get cluster info
    info = es.info()
    print(f"Cluster: {info['cluster_name']}")
    print(f"ES Version: {info['version']['number']}")
    
    # Get unique types (all logs)
    get_unique_types(es)
    
    # Get breakdown of types with input field
    get_input_types_breakdown(es)
    
    # Get actual logs with input field
    input_hits = get_logs_with_input(es, num_docs=100)
    
    print("\n✓ Exploration complete!")


if __name__ == "__main__":
    main()
