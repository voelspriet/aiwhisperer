"""
AIWhisperer GUI - Decode Widget

This module provides the decoding (restoration) tab functionality.
"""

import os

# Try PySide6 first, fall back to PyQt6
try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QTextEdit, QPushButton, QFileDialog,
        QGroupBox, QSplitter, QProgressBar, QMessageBox
    )
    from PySide6.QtCore import Qt, Signal, QThread
except ImportError:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QTextEdit, QPushButton, QFileDialog,
        QGroupBox, QSplitter, QProgressBar, QMessageBox
    )
    from PyQt6.QtCore import Qt, pyqtSignal as Signal, QThread


class DecodeWorker(QThread):
    """Background worker for decoding operations."""
    
    finished = Signal(str)  # decoded_text
    error = Signal(str)
    progress = Signal(str)
    
    def __init__(self, text, mapping):
        super().__init__()
        self.text = text
        self.mapping = mapping
    
    def run(self):
        try:
            self.progress.emit("Decoding document...")
            
            from aiwhisperer import decode
            
            decoded_text = decode(self.text, self.mapping)
            
            self.finished.emit(decoded_text)
            
        except Exception as e:
            self.error.emit(str(e))


class DecodeWidget(QWidget):
    """Widget for decoding/restoring documents."""
    
    status_message = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.current_file = None
        self.current_mapping = None
        self.mapping_path = None
        self._unsaved_changes = False
        self.worker = None
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the decode widget UI."""
        layout = QVBoxLayout(self)
        
        # Create splitter for input/output
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)
        
        # Left panel - Input
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 5, 0)
        
        # Input group
        input_group = QGroupBox("AI Output (with placeholders)")
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
        self.input_text.setPlaceholderText("Paste AI output with placeholders here...")
        self.input_text.textChanged.connect(self.on_text_changed)
        input_layout.addWidget(self.input_text)
        
        left_layout.addWidget(input_group)
        splitter.addWidget(left_panel)
        
        # Right panel - Output
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(5, 0, 0, 0)
        
        # Output group
        output_group = QGroupBox("Decoded Output")
        output_layout = QVBoxLayout(output_group)
        
        # Output text area
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText("Decoded document will appear here...")
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        
        right_layout.addWidget(output_group)
        splitter.addWidget(right_panel)
        
        # Set splitter sizes
        splitter.setSizes([400, 400])
        
        # Mapping file panel
        mapping_group = QGroupBox("Mapping File")
        mapping_layout = QHBoxLayout(mapping_group)
        
        self.mapping_label = QLabel("No mapping file selected")
        self.mapping_label.setStyleSheet("color: gray;")
        mapping_layout.addWidget(self.mapping_label, 1)
        
        browse_mapping_btn = QPushButton("Browse...")
        browse_mapping_btn.clicked.connect(self.browse_mapping)
        mapping_layout.addWidget(browse_mapping_btn)
        
        layout.addWidget(mapping_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        layout.addWidget(self.progress_bar)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.decode_btn = QPushButton("Decode Document")
        self.decode_btn.setStyleSheet("font-weight: bold; padding: 10px;")
        self.decode_btn.clicked.connect(self.decode_document)
        button_layout.addWidget(self.decode_btn)
        
        button_layout.addStretch()
        
        self.save_btn = QPushButton("Save Decoded Text...")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save_decoded_text)
        button_layout.addWidget(self.save_btn)
        
        layout.addLayout(button_layout)
    
    def browse_file(self):
        """Open file browser to select input file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open AI Output",
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
            
            # Try to auto-detect mapping file
            self.auto_detect_mapping(file_path)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load file:\n{e}")
    
    def auto_detect_mapping(self, file_path):
        """Try to auto-detect the mapping file based on input file name."""
        base_dir = os.path.dirname(file_path)
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        
        # Try common mapping file patterns
        patterns = [
            f"{base_name}_mapping.json",
            f"{base_name.replace('_sanitized', '')}_mapping.json",
            f"{base_name.replace('_ai_output', '')}_mapping.json",
            "mapping.json",
        ]
        
        for pattern in patterns:
            mapping_path = os.path.join(base_dir, pattern)
            if os.path.exists(mapping_path):
                self.load_mapping(mapping_path)
                self.status_message.emit(f"Auto-detected mapping: {pattern}")
                return
    
    def browse_mapping(self):
        """Open file browser to select mapping file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Mapping File",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        if file_path:
            self.load_mapping(file_path)
    
    def load_mapping(self, file_path):
        """Load a mapping file."""
        try:
            from aiwhisperer.mapper import Mapping
            
            self.current_mapping = Mapping.load(file_path)
            self.mapping_path = file_path
            self.mapping_label.setText(os.path.basename(file_path))
            self.mapping_label.setStyleSheet("")
            self.status_message.emit(f"Mapping loaded: {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load mapping:\n{e}")
    
    def on_text_changed(self):
        """Handle text changes in input area."""
        self._unsaved_changes = True
    
    def decode_document(self):
        """Start the decoding process."""
        text = self.input_text.toPlainText()
        if not text.strip():
            QMessageBox.warning(self, "Warning", "Please enter or load AI output first.")
            return
        
        if not self.current_mapping:
            QMessageBox.warning(self, "Warning", "Please load a mapping file first.")
            return
        
        # Disable UI during decoding
        self.decode_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.status_message.emit("Decoding document...")
        
        # Start worker thread
        self.worker = DecodeWorker(text, self.current_mapping)
        self.worker.finished.connect(self.on_decode_finished)
        self.worker.error.connect(self.on_decode_error)
        self.worker.progress.connect(self.status_message.emit)
        self.worker.start()
    
    def on_decode_finished(self, decoded_text):
        """Handle successful decoding."""
        self.output_text.setPlainText(decoded_text)
        
        # Enable save button
        self.save_btn.setEnabled(True)
        
        # Reset UI
        self.decode_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        self.status_message.emit("Decoding complete!")
        self._unsaved_changes = True
    
    def on_decode_error(self, error_msg):
        """Handle decoding error."""
        self.decode_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_message.emit("Decoding failed")
        QMessageBox.critical(self, "Decoding Error", f"Failed to decode document:\n{error_msg}")
    
    def save_decoded_text(self):
        """Save the decoded text to a file."""
        if not self.output_text.toPlainText():
            return
        
        # Suggest filename based on input file
        suggested_name = ""
        if self.current_file:
            base = os.path.splitext(os.path.basename(self.current_file))[0]
            suggested_name = f"{base}_decoded.txt"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Decoded Text",
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
    
    def has_unsaved_changes(self):
        """Check if there are unsaved changes."""
        return self._unsaved_changes and self.output_text.toPlainText()
    
    def apply_settings(self, settings):
        """Apply settings from QSettings."""
        pass  # No specific settings for decode widget yet
