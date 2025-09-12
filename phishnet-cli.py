#!/usr/bin/env python3
"""
PhishNet CLI Entry Point

Simple entry script that delegates to the unified CLI.
Usage: python phishnet-cli.py [command] [args...]
"""

if __name__ == "__main__":
    from src.cli.phishnet import main
    main()
