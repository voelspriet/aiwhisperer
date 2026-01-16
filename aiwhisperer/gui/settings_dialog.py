"""
AIWhisperer GUI - Settings Dialog

This module provides the settings/preferences dialog.
"""

# Try PySide6 first, fall back to PyQt6
try:
    from PySide6.QtWidgets import (
        QDialog, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QComboBox, QCheckBox, QPushButton,
        QGroupBox, QDialogButtonBox, QFileDialog, QLineEdit
    )
    from PySide6.QtCore import Qt
except ImportError:
    from PyQt6.QtWidgets import (
        QDialog, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QComboBox, QCheckBox, QPushButton,
        QGroupBox, QDialogButtonBox, QFileDialog, QLineEdit
    )
    from PyQt6.QtCore import Qt


class SettingsDialog(QDialog):
    """Settings/Preferences dialog."""
    
    LANGUAGES = [
        ("Dutch (nl)", "nl"),
        ("English (en)", "en"),
        ("German (de)", "de"),
        ("French (fr)", "fr"),
        ("Italian (it)", "it"),
        ("Spanish (es)", "es"),
    ]
    
    STRATEGIES = [
        ("Replace (reversible)", "replace"),
        ("Redact [REDACTED]", "redact"),
        ("Mask (j**@e****.com)", "mask"),
        ("Hash (SHA256)", "hash"),
    ]
    
    BACKENDS = [
        ("Hybrid (spaCy + patterns)", "hybrid"),
        ("Patterns only", "patterns"),
        ("spaCy NER only", "spacy"),
    ]
    
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setup_ui()
        self.load_settings()
    
    def setup_ui(self):
        """Set up the dialog UI."""
        self.setWindowTitle("Preferences")
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout(self)
        
        # Encoding defaults group
        encoding_group = QGroupBox("Encoding Defaults")
        encoding_layout = QGridLayout(encoding_group)
        
        # Default language
        encoding_layout.addWidget(QLabel("Default Language:"), 0, 0)
        self.language_combo = QComboBox()
        for name, code in self.LANGUAGES:
            self.language_combo.addItem(name, code)
        encoding_layout.addWidget(self.language_combo, 0, 1)
        
        # Default strategy
        encoding_layout.addWidget(QLabel("Default Strategy:"), 1, 0)
        self.strategy_combo = QComboBox()
        for name, code in self.STRATEGIES:
            self.strategy_combo.addItem(name, code)
        encoding_layout.addWidget(self.strategy_combo, 1, 1)
        
        # Default backend
        encoding_layout.addWidget(QLabel("Default Backend:"), 2, 0)
        self.backend_combo = QComboBox()
        for name, code in self.BACKENDS:
            self.backend_combo.addItem(name, code)
        encoding_layout.addWidget(self.backend_combo, 2, 1)
        
        # Include legend by default
        self.legend_checkbox = QCheckBox("Include legend for AI by default")
        encoding_layout.addWidget(self.legend_checkbox, 3, 0, 1, 2)
        
        layout.addWidget(encoding_group)
        
        # Output defaults group
        output_group = QGroupBox("Output Defaults")
        output_layout = QGridLayout(output_group)
        
        # Default output directory
        output_layout.addWidget(QLabel("Default Output Directory:"), 0, 0)
        
        dir_layout = QHBoxLayout()
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText("Same as input file")
        dir_layout.addWidget(self.output_dir_edit)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_output_dir)
        dir_layout.addWidget(browse_btn)
        
        output_layout.addLayout(dir_layout, 0, 1)
        
        layout.addWidget(output_group)
        
        # Add stretch
        layout.addStretch()
        
        # Dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel |
            QDialogButtonBox.StandardButton.RestoreDefaults
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        button_box.button(QDialogButtonBox.StandardButton.RestoreDefaults).clicked.connect(
            self.restore_defaults
        )
        layout.addWidget(button_box)
    
    def browse_output_dir(self):
        """Browse for output directory."""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            self.output_dir_edit.text()
        )
        if dir_path:
            self.output_dir_edit.setText(dir_path)
    
    def load_settings(self):
        """Load current settings into the dialog."""
        # Language
        lang = self.settings.value("default_language", "nl")
        for i in range(self.language_combo.count()):
            if self.language_combo.itemData(i) == lang:
                self.language_combo.setCurrentIndex(i)
                break
        
        # Strategy
        strategy = self.settings.value("default_strategy", "replace")
        for i in range(self.strategy_combo.count()):
            if self.strategy_combo.itemData(i) == strategy:
                self.strategy_combo.setCurrentIndex(i)
                break
        
        # Backend
        backend = self.settings.value("default_backend", "hybrid")
        for i in range(self.backend_combo.count()):
            if self.backend_combo.itemData(i) == backend:
                self.backend_combo.setCurrentIndex(i)
                break
        
        # Legend
        self.legend_checkbox.setChecked(
            self.settings.value("include_legend", True, type=bool)
        )
        
        # Output directory
        self.output_dir_edit.setText(
            self.settings.value("default_output_dir", "")
        )
    
    def save_settings(self):
        """Save settings from the dialog."""
        self.settings.setValue("default_language", self.language_combo.currentData())
        self.settings.setValue("default_strategy", self.strategy_combo.currentData())
        self.settings.setValue("default_backend", self.backend_combo.currentData())
        self.settings.setValue("include_legend", self.legend_checkbox.isChecked())
        self.settings.setValue("default_output_dir", self.output_dir_edit.text())
    
    def restore_defaults(self):
        """Restore default settings."""
        self.language_combo.setCurrentIndex(0)  # Dutch
        self.strategy_combo.setCurrentIndex(0)  # Replace
        self.backend_combo.setCurrentIndex(0)   # Hybrid
        self.legend_checkbox.setChecked(True)
        self.output_dir_edit.clear()
    
    def accept(self):
        """Handle dialog acceptance."""
        self.save_settings()
        super().accept()
