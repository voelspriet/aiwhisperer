"""
AIWhisperer GUI - Main Window

This module provides the main application window with tabs for encoding and decoding.
"""

import os
import sys

# Try PySide6 first, fall back to PyQt6
try:
    from PySide6.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QMenuBar, QMenu, QStatusBar, QMessageBox,
        QFileDialog, QLabel
    )
    from PySide6.QtCore import Qt, QSettings
    from PySide6.QtGui import QAction, QKeySequence
except ImportError:
    from PyQt6.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QMenuBar, QMenu, QStatusBar, QMessageBox,
        QFileDialog, QLabel
    )
    from PyQt6.QtCore import Qt, QSettings
    from PyQt6.QtGui import QAction, QKeySequence

from aiwhisperer.gui.convert_widget import ConvertWidget
from aiwhisperer.gui.encode_widget import EncodeWidget
from aiwhisperer.gui.decode_widget import DecodeWidget
from aiwhisperer.gui.settings_dialog import SettingsDialog


class MainWindow(QMainWindow):
    """Main application window for AIWhisperer GUI."""
    
    def __init__(self):
        super().__init__()
        self.settings = QSettings("AIWhisperer", "AIWhisperer")
        self.setup_ui()
        self.setup_menu()
        self.load_settings()
    
    def setup_ui(self):
        """Set up the main user interface."""
        self.setWindowTitle("AIWhisperer - PDF to Text with Privacy")
        self.setMinimumSize(900, 700)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Convert tab (new simplified interface)
        self.convert_widget = ConvertWidget()
        self.tab_widget.addTab(self.convert_widget, "Convert PDF")
        
        # Decode tab
        self.decode_widget = DecodeWidget()
        self.tab_widget.addTab(self.decode_widget, "Decode AI Output")
        
        # Advanced tab (old encode widget)
        self.encode_widget = EncodeWidget()
        self.tab_widget.addTab(self.encode_widget, "Advanced")
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Drop a PDF to get started")
        
        # Connect signals
        self.convert_widget.status_message.connect(self.status_bar.showMessage)
        self.encode_widget.status_message.connect(self.status_bar.showMessage)
        self.decode_widget.status_message.connect(self.status_bar.showMessage)
    
    def setup_menu(self):
        """Set up the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        open_action = QAction("&Open File...", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menubar.addMenu("&Edit")
        
        settings_action = QAction("&Preferences...", self)
        settings_action.setShortcut(QKeySequence("Ctrl+,"))
        settings_action.triggered.connect(self.show_settings)
        edit_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        check_deps_action = QAction("Check &Dependencies...", self)
        check_deps_action.triggered.connect(self.check_dependencies)
        help_menu.addAction(check_deps_action)
        
        help_menu.addSeparator()
        
        about_action = QAction("&About AIWhisperer", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def open_file(self):
        """Open a file and load it into the appropriate tab."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open File",
            self.settings.value("last_directory", ""),
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            self.settings.setValue("last_directory", os.path.dirname(file_path))
            
            # Determine which tab to use based on current tab
            current_tab = self.tab_widget.currentIndex()
            if current_tab == 0:
                self.encode_widget.load_file(file_path)
            else:
                self.decode_widget.load_file(file_path)
    
    def show_settings(self):
        """Show the settings dialog."""
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec():
            self.apply_settings()
    
    def apply_settings(self):
        """Apply settings to all widgets."""
        self.convert_widget.apply_settings(self.settings)
        self.encode_widget.apply_settings(self.settings)
        self.decode_widget.apply_settings(self.settings)
    
    def check_dependencies(self):
        """Check and display dependency status."""
        from aiwhisperer.gui.dependency_checker import check_all_dependencies
        
        results = check_all_dependencies()
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Dependency Check")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText("AIWhisperer Dependency Status")
        msg.setDetailedText(results)
        msg.exec()
    
    def show_about(self):
        """Show the about dialog."""
        QMessageBox.about(
            self,
            "About AIWhisperer",
            "<h2>AIWhisperer</h2>"
            "<p>Version 0.5.0</p>"
            "<p>PDF to text with optional sanitization for AI analysis.</p>"
            "<p>AIWhisperer converts large PDFs to text and optionally sanitizes "
            "sensitive information before uploading to cloud AI services like "
            "NotebookLM, Claude, or ChatGPT.</p>"
            "<p><b>Key Features:</b></p>"
            "<ul>"
            "<li>PDF to text conversion with OCR support</li>"
            "<li>Optional PII sanitization for confidential files</li>"
            "<li>Google Drive integration for easy AI upload</li>"
            "<li>Reversible anonymization with mapping files</li>"
            "<li>Support for multiple languages</li>"
            "</ul>"
            "<p>License: CC0-1.0 Public Domain</p>"
        )
    
    def load_settings(self):
        """Load saved settings."""
        # Restore window geometry
        geometry = self.settings.value("window_geometry")
        if geometry:
            self.restoreGeometry(geometry)
        
        # Apply settings to widgets
        self.apply_settings()
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Save window geometry
        self.settings.setValue("window_geometry", self.saveGeometry())
        
        # Check for unsaved changes
        if self.encode_widget.has_unsaved_changes() or self.decode_widget.has_unsaved_changes():
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "You have unsaved changes. Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
        
        event.accept()
