#!/usr/bin/env python3
"""
AIWhisperer GUI Application - Main Entry Point

This module provides the main entry point for the AIWhisperer GUI application.
"""

import sys
import os

# Try PySide6 first, fall back to PyQt6
try:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QIcon
except ImportError:
    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QIcon
    except ImportError:
        print("Error: PySide6 or PyQt6 is required for the GUI.")
        print("Install with: pip install PySide6")
        sys.exit(1)

from aiwhisperer.gui.main_window import MainWindow


def main():
    """Main entry point for the GUI application."""
    # Enable High DPI scaling
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    app.setApplicationName("AIWhisperer")
    app.setApplicationVersion("0.3.0")
    app.setOrganizationName("AIWhisperer")
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
