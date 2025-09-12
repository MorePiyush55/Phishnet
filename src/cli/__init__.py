"""
PhishNet CLI Package

Unified command line interface for all PhishNet operations.
Replaces scattered if __name__ == '__main__' blocks throughout the codebase.
"""

from .phishnet import main

__all__ = ['main']
