#!/usr/bin/env python3
"""
run_analysis.py - Orchestration script for scheduled honeypot analysis

Runs the full pipeline:
1. Query T-Pot ES for recent sessions with shell commands
2. Analyze sessions using LLM
3. Save results with timestamp

Configuration is loaded from config.yml and .env files.
See config.py for details.

Usage:
    python run_analysis.py
    python run_analysis.py --hours 6
    python run_analysis.py --days 7
    python run_analysis.py --hours 24 --workers 4   # Parallel processing
    
Cron examples:
    # Every 12 hours at midnight and noon
    0 0,12 * * * cd /path/to/project && python run_analysis.py >> /var/log/honeypot_analysis.log 2>&1
    
    # Every 6 hours
    0 */6 * * * cd /path/to/project && python run_analysis.py --hours 6 >> /var/log/honeypot_analysis.log 2>&1
    
    # Daily analysis of last 7 days
    0 0 * * * cd /path/to/project && python run_analysis.py --days 7 >> /var/log/honeypot_analysis.log 2>&1
"""

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from config import config, print_config


def run_command(cmd, description):
    """Run a command and handle output."""
    print(f"\n{'='*60}")
    print(f"STEP: {description}")
    print(f"{'='*60}")
    print(f"Running: {' '.join(cmd)}\n")
    
    result = subprocess.run(
        cmd,
        capture_output=False,  # Let output flow to console
        text=True
    )
    
    if result.returncode != 0:
        print(f"\n✗ Command failed with return code {result.returncode}")
        return False
    return True


def main():
    # Build help text with config values
    hours_help = f"Hours to look back for logs (default from config: {config.analysis.lookback_hours or 'not set'})"
    days_help = f"Days to look back for logs (default from config: {config.analysis.lookback_days or 'not set'})"
    
    parser = argparse.ArgumentParser(
        description="Run full honeypot analysis pipeline"
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
        "--output-dir",
        type=str,
        default=config.analysis.output_dir,
        help=f"Directory to store results (default: {config.analysis.output_dir})"
    )
    parser.add_argument(
        "--min-commands",
        type=int,
        default=config.analysis.min_commands,
        help=f"Minimum commands per session to analyze (default: {config.analysis.min_commands})"
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=config.analysis.max_sessions,
        help=f"Maximum sessions to analyze (default: {config.analysis.max_sessions or 'no limit'})"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel workers for LLM analysis (default: 1)"
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Show current configuration and exit"
    )
    
    args = parser.parse_args()
    
    # Show config if requested
    if args.show_config:
        print_config()
        return
    
    # Determine lookback hours from args or config
    if args.hours is not None:
        lookback_hours = args.hours
    elif args.days is not None:
        lookback_hours = args.days * 24
    else:
        lookback_hours = config.analysis.total_hours
    
    # Create timestamped output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir) / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("="*60)
    print("T-POT HONEYPOT ANALYSIS PIPELINE")
    print("="*60)
    print(f"Timestamp: {timestamp}")
    print(f"Looking back: {lookback_hours} hours ({lookback_hours/24:.1f} days)")
    print(f"Output directory: {output_dir}")
    print(f"Min commands per session: {args.min_commands}")
    if args.max_sessions:
        print(f"Max sessions to analyze: {args.max_sessions}")
    print(f"Workers: {args.workers} {'(parallel)' if args.workers > 1 else '(sequential)'}")
    print(f"\nElasticsearch: {config.elasticsearch.host}:{config.elasticsearch.port}")
    print(f"LM Studio: {config.lm_studio.host}:{config.lm_studio.port}")
    
    # Get the directory where this script lives
    script_dir = Path(__file__).parent.resolve()
    
    # Step 1: Query Elasticsearch
    sessions_file = output_dir / "sessions.json"
    llm_file = output_dir / "sessions_for_llm.txt"
    
    query_cmd = [
        sys.executable,
        str(script_dir / "query_tpot_es.py"),
        "--hours", str(lookback_hours),
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
    summary_file = output_dir / "analysis_report_summary.md"
    
    analyze_cmd = [
        sys.executable,
        str(script_dir / "analyze_sessions.py"),
        "--input", str(sessions_file),
        "--output", str(results_file),
        "--report", str(report_file),
        "--summary", str(summary_file),
        "--min-commands", str(args.min_commands),
        "--workers", str(args.workers)
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
    for f in sorted(output_dir.iterdir()):
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
