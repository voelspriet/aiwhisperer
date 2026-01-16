"""
AIWhisperer GUI - Encode Widget

This module provides the encoding (sanitization) tab functionality.
"""

import os
import json

# Try PySide6 first, fall back to PyQt6
try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QTextEdit, QPushButton, QComboBox, QCheckBox,
        QFileDialog, QGroupBox, QSplitter, QProgressBar,
        QMessageBox
    )
    from PySide6.QtCore import Qt, Signal, QThread
except ImportError:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QTextEdit, QPushButton, QComboBox, QCheckBox,
        QFileDialog, QGroupBox, QSplitter, QProgressBar,
        QMessageBox
    )
    from PyQt6.QtCore import Qt, pyqtSignal as Signal, QThread


class EncodeWorker(QThread):
    """Background worker for encoding operations."""
    
    finished = Signal(str, object)  # sanitized_text, mapping
    error = Signal(str)
    progress = Signal(str)
    
    def __init__(self, text, language, strategy, backend, include_legend):
        super().__init__()
        self.text = text
        self.language = language
        self.strategy = strategy
        self.backend = backend
        self.include_legend = include_legend
    
    def run(self):
        try:
            self.progress.emit("Detecting sensitive information...")
            
            from aiwhisperer.encoder import encode, generate_legend
            
            self.progress.emit("Encoding document...")
            sanitized_text, mapping = encode(
                self.text,
                backend=self.backend,
                strategy=self.strategy,
                language=self.language
            )
            
            if self.include_legend:
                self.progress.emit("Generating legend...")
                legend = generate_legend(mapping)
                sanitized_text = legend + "\n\n" + sanitized_text
            
            self.finished.emit(sanitized_text, mapping)
            
        except Exception as e:
            self.error.emit(str(e))


class EncodeWidget(QWidget):
    """Widget for encoding/sanitizing documents."""
    
    status_message = Signal(str)
    
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
    
    def __init__(self):
        super().__init__()
        self.current_file = None
        self.current_mapping = None
        self._unsaved_changes = False
        self.worker = None
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the encode widget UI."""
        layout = QVBoxLayout(self)
        
        # Create splitter for input/output
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)
        
        # Left panel - Input
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 5, 0)
        
        # Input group
        input_group = QGroupBox("Input Document")
        input_layout = QVBoxLayout(input_group)
        
        # File selection row
        file_row = QHBoxLayout()
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("color: gray;")
        file_row.addWidget(self.file_label, 1)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_file)
        file_row.addWidget(browse_btn)
        input_layout.addLayout(file_row)
        
        # Input text area
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Paste or load document text here...")
        self.input_text.textChanged.connect(self.on_text_changed)
        input_layout.addWidget(self.input_text)
        
        left_layout.addWidget(input_group)
        splitter.addWidget(left_panel)
        
        # Right panel - Output
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(5, 0, 0, 0)
        
        # Output group
        output_group = QGroupBox("Sanitized Output")
        output_layout = QVBoxLayout(output_group)
        
        # Output text area
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText("Sanitized document will appear here...")
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        
        right_layout.addWidget(output_group)
        splitter.addWidget(right_panel)
        
        # Set splitter sizes
        splitter.setSizes([400, 400])
        
        # Options panel
        options_group = QGroupBox("Options")
        options_layout = QGridLayout(options_group)
        
        # Language selector
        options_layout.addWidget(QLabel("Language:"), 0, 0)
        self.language_combo = QComboBox()
        for name, code in self.LANGUAGES:
            self.language_combo.addItem(name, code)
        options_layout.addWidget(self.language_combo, 0, 1)
        
        # Strategy selector
        options_layout.addWidget(QLabel("Strategy:"), 0, 2)
        self.strategy_combo = QComboBox()
        for name, code in self.STRATEGIES:
            self.strategy_combo.addItem(name, code)
        options_layout.addWidget(self.strategy_combo, 0, 3)
        
        # Backend selector
        options_layout.addWidget(QLabel("Backend:"), 1, 0)
        self.backend_combo = QComboBox()
        for name, code in self.BACKENDS:
            self.backend_combo.addItem(name, code)
        options_layout.addWidget(self.backend_combo, 1, 1)
        
        # Include legend checkbox
        self.legend_checkbox = QCheckBox("Include legend for AI")
        self.legend_checkbox.setChecked(True)
        options_layout.addWidget(self.legend_checkbox, 1, 2, 1, 2)
        
        layout.addWidget(options_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        layout.addWidget(self.progress_bar)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.encode_btn = QPushButton("Encode Document")
        self.encode_btn.setStyleSheet("font-weight: bold; padding: 10px;")
        self.encode_btn.clicked.connect(self.encode_document)
        button_layout.addWidget(self.encode_btn)
        
        button_layout.addStretch()
        
        self.save_text_btn = QPushButton("Save Sanitized Text...")
        self.save_text_btn.setEnabled(False)
        self.save_text_btn.clicked.connect(self.save_sanitized_text)
        button_layout.addWidget(self.save_text_btn)
        
        self.save_mapping_btn = QPushButton("Save Mapping...")
        self.save_mapping_btn.setEnabled(False)
        self.save_mapping_btn.clicked.connect(self.save_mapping)
        button_layout.addWidget(self.save_mapping_btn)
        
        layout.addLayout(button_layout)
    
    def browse_file(self):
        """Open file browser to select input file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Document",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.load_file(file_path)
    
    def load_file(self, file_path):
        """Load a file into the input text area."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.input_text.setPlainText(content)
            self.current_file = file_path
            self.file_label.setText(os.path.basename(file_path))
            self.file_label.setStyleSheet("")
            self.status_message.emit(f"Loaded: {file_path}")
            self._unsaved_changes = False
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load file:\n{e}")
    
    def on_text_changed(self):
        """Handle text changes in input area."""
        self._unsaved_changes = True
    
    def encode_document(self):
        """Start the encoding process."""
        text = self.input_text.toPlainText()
        if not text.strip():
            QMessageBox.warning(self, "Warning", "Please enter or load a document first.")
            return
        
        # Get options
        language = self.language_combo.currentData()
        strategy = self.strategy_combo.currentData()
        backend = self.backend_combo.currentData()
        include_legend = self.legend_checkbox.isChecked()
        
        # Disable UI during encoding
        self.encode_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.status_message.emit("Encoding document...")
        
        # Start worker thread
        self.worker = EncodeWorker(text, language, strategy, backend, include_legend)
        self.worker.finished.connect(self.on_encode_finished)
        self.worker.error.connect(self.on_encode_error)
        self.worker.progress.connect(self.status_message.emit)
        self.worker.start()
    
    def on_encode_finished(self, sanitized_text, mapping):
        """Handle successful encoding."""
        self.output_text.setPlainText(sanitized_text)
        self.current_mapping = mapping
        
        # Enable save buttons
        self.save_text_btn.setEnabled(True)
        self.save_mapping_btn.setEnabled(True)
        
        # Reset UI
        self.encode_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        # Count replacements
        if hasattr(mapping, 'entries'):
            count = len(mapping.entries)
        else:
            count = len(mapping._forward) if hasattr(mapping, '_forward') else 0
        
        self.status_message.emit(f"Encoding complete! {count} items replaced.")
        self._unsaved_changes = True
    
    def on_encode_error(self, error_msg):
        """Handle encoding error."""
        self.encode_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_message.emit("Encoding failed")
        QMessageBox.critical(self, "Encoding Error", f"Failed to encode document:\n{error_msg}")
    
    def save_sanitized_text(self):
        """Save the sanitized text to a file."""
        if not self.output_text.toPlainText():
            return
        
        # Suggest filename based on input file
        suggested_name = ""
        if self.current_file:
            base = os.path.splitext(os.path.basename(self.current_file))[0]
            suggested_name = f"{base}_sanitized.txt"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Sanitized Text",
            suggested_name,
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.output_text.toPlainText())
                self.status_message.emit(f"Saved: {file_path}")
                self._unsaved_changes = False
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file:\n{e}")
    
    def save_mapping(self):
        """Save the mapping to a JSON file."""
        if not self.current_mapping:
            return
        
        # Suggest filename based on input file
        suggested_name = ""
        if self.current_file:
            base = os.path.splitext(os.path.basename(self.current_file))[0]
            suggested_name = f"{base}_mapping.json"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Mapping",
            suggested_name,
            "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                self.current_mapping.save(file_path)
                self.status_message.emit(f"Mapping saved: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save mapping:\n{e}")
    
    def has_unsaved_changes(self):
        """Check if there are unsaved changes."""
        return self._unsaved_changes and self.output_text.toPlainText()
    
    def apply_settings(self, settings):
        """Apply settings from QSettings."""
        # Set default language
        default_lang = settings.value("default_language", "nl")
        for i in range(self.language_combo.count()):
            if self.language_combo.itemData(i) == default_lang:
                self.language_combo.setCurrentIndex(i)
                break
        
        # Set default strategy
        default_strategy = settings.value("default_strategy", "replace")
        for i in range(self.strategy_combo.count()):
            if self.strategy_combo.itemData(i) == default_strategy:
                self.strategy_combo.setCurrentIndex(i)
                break
        
        # Set default backend
        default_backend = settings.value("default_backend", "hybrid")
        for i in range(self.backend_combo.count()):
            if self.backend_combo.itemData(i) == default_backend:
                self.backend_combo.setCurrentIndex(i)
                break
        
        # Set legend checkbox
        include_legend = settings.value("include_legend", True, type=bool)
        self.legend_checkbox.setChecked(include_legend)
