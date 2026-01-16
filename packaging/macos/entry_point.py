#!/usr/bin/env python3
"""
Entry point script for PyInstaller builds.

This script uses absolute imports to avoid the "relative import with no known
parent package" error that occurs when PyInstaller runs cli.py directly.
"""

from aiwhisperer.cli import main

if __name__ == '__main__':
    main()
