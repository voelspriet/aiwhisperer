"""
AIWhisperer GUI - Main Window

Digital Digging aesthetic: Dark theme, visual pipeline workflow, amber accents.
Professional investigative tool feel.
"""

import os
import sys
import webbrowser

# Try PySide6 first, fall back to PyQt6
try:
    from PySide6.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QMenuBar, QMenu, QStatusBar, QMessageBox,
        QFileDialog, QLabel, QFrame, QPushButton,
        QStackedWidget, QApplication, QTabWidget
    )
    from PySide6.QtCore import Qt, QSettings
    from PySide6.QtGui import QAction, QKeySequence, QFont
except ImportError:
    from PyQt6.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QMenuBar, QMenu, QStatusBar, QMessageBox,
        QFileDialog, QLabel, QFrame, QPushButton,
        QStackedWidget, QApplication, QTabWidget
    )
    from PyQt6.QtCore import Qt, QSettings
    from PyQt6.QtGui import QAction, QKeySequence, QFont

from aiwhisperer.gui.convert_widget import ConvertWidget
from aiwhisperer.gui.decode_widget import DecodeWidget
from aiwhisperer.gui.encode_widget import EncodeWidget
from aiwhisperer.gui.settings_dialog import SettingsDialog

# Version
VERSION = "0.5.0"

# Digital Digging color palette
COLORS = {
    'bg_dark': '#1a1a2e',
    'bg_medium': '#16213e',
    'bg_light': '#0f3460',
    'accent': '#e6a919',
    'accent_hover': '#f5b82e',
    'text_primary': '#eaeaea',
    'text_secondary': '#a0a0a0',
    'text_muted': '#666666',
    'border': '#2a2a4a',
    'success': '#4ade80',
    'error': '#f87171',
}

# Dark theme stylesheet
DARK_STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", sans-serif;
}}

QLabel {{
    color: {COLORS['text_primary']};
}}

QPushButton {{
    background-color: {COLORS['bg_light']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
}}

QPushButton:hover {{
    background-color: {COLORS['accent']};
    color: {COLORS['bg_dark']};
    border-color: {COLORS['accent']};
}}

QPushButton:disabled {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_muted']};
}}

QTextEdit, QPlainTextEdit {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 8px;
    selection-background-color: {COLORS['accent']};
}}

QComboBox {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 6px 12px;
}}

QComboBox:hover {{
    border-color: {COLORS['accent']};
}}

QComboBox QAbstractItemView {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_primary']};
    selection-background-color: {COLORS['accent']};
}}

QProgressBar {{
    background-color: {COLORS['bg_medium']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    text-align: center;
    color: {COLORS['text_primary']};
}}

QProgressBar::chunk {{
    background-color: {COLORS['accent']};
    border-radius: 3px;
}}

QGroupBox {{
    background-color: {COLORS['bg_medium']};
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: 600;
}}

QGroupBox::title {{
    color: {COLORS['text_secondary']};
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 8px;
}}

QMenuBar {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    border-bottom: 1px solid {COLORS['border']};
}}

QMenuBar::item:selected {{
    background-color: {COLORS['bg_light']};
}}

QMenu {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
}}

QMenu::item:selected {{
    background-color: {COLORS['accent']};
    color: {COLORS['bg_dark']};
}}

QStatusBar {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_secondary']};
    border-top: 1px solid {COLORS['border']};
}}

QScrollBar:vertical {{
    background-color: {COLORS['bg_dark']};
    width: 12px;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS['border']};
    border-radius: 6px;
    min-height: 20px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLORS['text_muted']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QSplitter::handle {{
    background-color: {COLORS['border']};
}}
"""


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
        self.setWindowTitle("AIWhisperer")
        self.setMinimumSize(900, 700)

        # Apply dark theme
        self.setStyleSheet(DARK_STYLESHEET)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_medium']};
                border-bottom: 1px solid {COLORS['border']};
                padding: 12px 20px;
            }}
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 12, 20, 12)

        # Title
        title = QLabel("AIWhisperer")
        title.setStyleSheet(f"""
            font-size: 20px;
            font-weight: 700;
            color: {COLORS['text_primary']};
        """)
        header_layout.addWidget(title)

        # Tagline
        tagline = QLabel("Whisper your documents to AI")
        tagline.setStyleSheet(f"""
            font-size: 13px;
            color: {COLORS['text_secondary']};
            margin-left: 12px;
        """)
        header_layout.addWidget(tagline)

        header_layout.addStretch()

        # Version
        version_label = QLabel(f"v{VERSION}")
        version_label.setStyleSheet(f"""
            font-size: 11px;
            color: {COLORS['text_muted']};
        """)
        header_layout.addWidget(version_label)

        layout.addWidget(header)

        # Content area with padding
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(0)

        # Tab widget with custom styling
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                background-color: {COLORS['bg_medium']};
                padding: 16px;
            }}
            QTabBar::tab {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_secondary']};
                border: 1px solid {COLORS['border']};
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 10px 20px;
                margin-right: 4px;
                font-weight: 500;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['bg_medium']};
                color: {COLORS['accent']};
                border-bottom: 2px solid {COLORS['accent']};
            }}
            QTabBar::tab:hover:!selected {{
                background-color: {COLORS['bg_light']};
                color: {COLORS['text_primary']};
            }}
        """)
        content_layout.addWidget(self.tab_widget)

        layout.addWidget(content)

        # Convert tab (main workflow)
        self.convert_widget = ConvertWidget()
        self.tab_widget.addTab(self.convert_widget, "Convert PDF")

        # Decode tab
        self.decode_widget = DecodeWidget()
        self.tab_widget.addTab(self.decode_widget, "Decode AI Output")

        # Advanced tab
        self.encode_widget = EncodeWidget()
        self.tab_widget.addTab(self.encode_widget, "Advanced")

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Drop a PDF to get started")

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
