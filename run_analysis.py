#!/usr/bin/env python3
"""
run_analysis.py - Orchestration script for scheduled honeypot analysis

Runs the full pipeline:
1. Query T-Pot ES for recent sessions with shell commands
2. Analyze sessions using LLM
3. Save results with timestamp

Designed to be run via cron every 6 or 12 hours.

Usage:
    python run_analysis.py
    python run_analysis.py --hours 6
    
Cron examples:
    # Every 12 hours at midnight and noon
    0 0,12 * * * cd /path/to/project && python run_analysis.py --hours 12
    
    # Every 6 hours
    0 */6 * * * cd /path/to/project && python run_analysis.py --hours 6
"""

import argparse
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

from config import OUTPUT_DIR


def run_command(cmd, description):
    """Run a command and handle output."""
    print(f"\n{'='*60}")
    print(f"STEP: {description}")
    print(f"{'='*60}")
    print(f"Running: {' '.join(cmd)}\n")
    
    result = subprocess.run(cmd, capture_output=False, text=True)
    
    if result.returncode != 0:
        print(f"\n✗ Command failed with return code {result.returncode}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Run full honeypot analysis pipeline"
    )
    parser.add_argument(
        "--hours", type=int, default=12,
        help="Hours to look back for logs (default: 12)"
    )
    parser.add_argument(
        "--output-dir", type=str, default=str(OUTPUT_DIR),
        help=f"Directory to store results (default: {OUTPUT_DIR})"
    )
    parser.add_argument(
        "--min-commands", type=int, default=2,
        help="Minimum commands per session to analyze (default: 2)"
    )
    parser.add_argument(
        "--max-sessions", type=int, default=None,
        help="Maximum sessions to analyze (default: no limit)"
    )
    
    args = parser.parse_args()
    
    # Create timestamped output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir) / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("="*60)
    print("T-POT HONEYPOT ANALYSIS PIPELINE")
    print("="*60)
    print(f"Timestamp: {timestamp}")
    print(f"Looking back: {args.hours} hours")
    print(f"Output directory: {output_dir}")
    print(f"Min commands per session: {args.min_commands}")
    if args.max_sessions:
        print(f"Max sessions to analyze: {args.max_sessions}")
    
    # Get script directory
    script_dir = Path(__file__).parent.resolve()
    
    # Step 1: Query Elasticsearch
    sessions_file = output_dir / "sessions.json"
    llm_file = output_dir / "sessions_for_llm.txt"
    
    query_cmd = [
        sys.executable,
        str(script_dir / "query_tpot_es.py"),
        "--hours", str(args.hours),
        "--output", str(sessions_file),
        "--llm-output", str(llm_file)
    ]
    
    if not run_command(query_cmd, "Query T-Pot Elasticsearch"):
        print("\n✗ Pipeline failed at query step")
        sys.exit(1)
    
    # Check if we got any sessions
    if not sessions_file.exists() or sessions_file.stat().st_size < 10:
        print("\n⚠ No sessions found, skipping analysis")
        sys.exit(0)
    
    # Step 2: Analyze with LLM
    results_file = output_dir / "analysis_results.json"
    report_file = output_dir / "analysis_report.md"
    
    analyze_cmd = [
        sys.executable,
        str(script_dir / "analyze_sessions.py"),
        "--input", str(sessions_file),
        "--output", str(results_file),
        "--report", str(report_file),
        "--min-commands", str(args.min_commands)
    ]
    
    if args.max_sessions:
        analyze_cmd.extend(["--limit", str(args.max_sessions)])
    
    if not run_command(analyze_cmd, "Analyze sessions with LLM"):
        print("\n✗ Pipeline failed at analysis step")
        sys.exit(1)
    
    # Summary
    print("\n" + "="*60)
    print("PIPELINE COMPLETE")
    print("="*60)
    print(f"\nOutput files in {output_dir}/:")
    for f in output_dir.iterdir():
        if f.is_file():
            size = f.stat().st_size
            print(f"  - {f.name} ({size:,} bytes)")
    
    # Create/update symlink to latest results
    latest_link = Path(args.output_dir) / "latest"
    if latest_link.exists() or latest_link.is_symlink():
        latest_link.unlink()
    latest_link.symlink_to(timestamp)
    print(f"\n✓ Updated 'latest' symlink -> {timestamp}")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    main()
