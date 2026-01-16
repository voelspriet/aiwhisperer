#!/usr/bin/env python3
"""
Entry point script for PyInstaller GUI builds.

This script uses absolute imports to avoid the "relative import with no known
parent package" error that occurs when PyInstaller runs modules directly.
"""

from aiwhisperer.gui.main import main

if __name__ == '__main__':
    main()
