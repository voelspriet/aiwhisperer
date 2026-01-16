"""
AIWhisperer GUI - Convert Widget

Simplified PDF-to-text conversion with optional sanitization.
Designed for newbie users with big buttons and clear workflow.
"""

import os
from pathlib import Path

# Try PySide6 first, fall back to PyQt6
try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QTextEdit, QPushButton, QComboBox, QCheckBox,
        QFileDialog, QGroupBox, QProgressBar, QFrame,
        QMessageBox, QSizePolicy
    )
    from PySide6.QtCore import Qt, Signal, QThread, QMimeData
    from PySide6.QtGui import QDragEnterEvent, QDropEvent, QFont
except ImportError:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QTextEdit, QPushButton, QComboBox, QCheckBox,
        QFileDialog, QGroupBox, QProgressBar, QFrame,
        QMessageBox, QSizePolicy
    )
    from PyQt6.QtCore import Qt, pyqtSignal as Signal, QThread, QMimeData
    from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QFont


class ConvertWorker(QThread):
    """Background worker for PDF conversion operations."""
    
    finished = Signal(str, dict, object)  # text, metadata, mapping (or None)
    error = Signal(str)
    progress = Signal(str)
    
    def __init__(self, pdf_path, output_dir, sanitize=False, language='nl'):
        super().__init__()
        self.pdf_path = pdf_path
        self.output_dir = output_dir
        self.sanitize = sanitize
        self.language = language
    
    def run(self):
        try:
            self.progress.emit("Converting PDF to text...")
            
            from pathlib import Path
            from aiwhisperer.converter import convert_pdf
            
            text, metadata = convert_pdf(
                self.pdf_path,
                output_dir=self.output_dir,
                backend='auto',
            )
            
            mapping = None
            
            if self.sanitize:
                self.progress.emit("Sanitizing sensitive information...")
                
                from aiwhisperer.encoder import encode, generate_legend
                
                sanitized_text, mapping = encode(
                    text,
                    backend='hybrid',
                    strategy='replace',
                    language=self.language
                )
                
                # Add legend header
                legend = generate_legend(mapping)
                text = legend + "\n\n" + sanitized_text
                
                # Save sanitized text to disk
                pdf_path = Path(self.pdf_path)
                output_dir = Path(self.output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
                
                # Save sanitized text
                sanitized_file = output_dir / f"{pdf_path.stem}_sanitized.txt"
                with open(sanitized_file, 'w', encoding='utf-8') as f:
                    f.write(text)
                
                # Save mapping file automatically
                mapping_file = output_dir / f"{pdf_path.stem}_mapping.json"
                mapping.save(str(mapping_file))
                
                # Update metadata
                metadata['sanitized'] = True
                metadata['entities_replaced'] = len(mapping.entries) if hasattr(mapping, 'entries') else 0
                metadata['output_file'] = str(sanitized_file)
                metadata['mapping_file'] = str(mapping_file)
            
            self.finished.emit(text, metadata, mapping)
            
        except Exception as e:
            self.error.emit(str(e))


# Digital Digging color palette
COLORS = {
    'bg_dark': '#1a1a2e',
    'bg_medium': '#16213e',
    'bg_light': '#0f3460',
    'accent': '#e6a919',
    'text_primary': '#eaeaea',
    'text_secondary': '#a0a0a0',
    'text_muted': '#666666',
    'border': '#2a2a4a',
    'success': '#4ade80',
}


class DropZone(QFrame):
    """Drag-and-drop zone for PDF files."""

    file_dropped = Signal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        self.setMinimumHeight(180)
        self._apply_default_style()

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)

        self.icon_label = QLabel("PDF")
        self.icon_label.setStyleSheet(f"""
            font-size: 28px;
            font-weight: bold;
            color: {COLORS['text_muted']};
            padding: 8px 16px;
            border: 2px solid {COLORS['border']};
            border-radius: 8px;
            background-color: {COLORS['bg_medium']};
        """)
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.icon_label)

        self.text_label = QLabel("Drop PDF here or click to browse")
        self.text_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 14px;")
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.text_label)

        self.file_label = QLabel("")
        self.file_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: bold; font-size: 13px;")
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.file_label)

        self.size_label = QLabel("")
        self.size_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px;")
        self.size_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.size_label)

    def _apply_default_style(self):
        self.setStyleSheet(f"""
            DropZone {{
                border: 2px dashed {COLORS['border']};
                border-radius: 12px;
                background-color: {COLORS['bg_dark']};
            }}
            DropZone:hover {{
                border-color: {COLORS['accent']};
                background-color: {COLORS['bg_medium']};
            }}
        """)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and urls[0].toLocalFile().lower().endswith('.pdf'):
                event.acceptProposedAction()
                self.setStyleSheet(f"""
                    DropZone {{
                        border: 2px dashed {COLORS['accent']};
                        border-radius: 12px;
                        background-color: {COLORS['bg_light']};
                    }}
                """)

    def dragLeaveEvent(self, event):
        self._apply_default_style()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            if file_path.lower().endswith('.pdf'):
                self.file_dropped.emit(file_path)
        self.dragLeaveEvent(event)

    def mousePressEvent(self, event):
        self.file_dropped.emit("")

    def set_file(self, file_path):
        if file_path:
            self.file_label.setText(os.path.basename(file_path))
            self.text_label.setText("PDF selected:")
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            self.size_label.setText(f"{size_mb:.1f} MB")
            self.icon_label.setText("OK")
            self.icon_label.setStyleSheet(f"""
                font-size: 28px;
                font-weight: bold;
                color: {COLORS['success']};
                padding: 8px 16px;
                border: 2px solid {COLORS['success']};
                border-radius: 8px;
                background-color: {COLORS['bg_medium']};
            """)
        else:
            self.file_label.setText("")
            self.size_label.setText("")
            self.text_label.setText("Drop PDF here or click to browse")
            self.icon_label.setText("PDF")
            self.icon_label.setStyleSheet(f"""
                font-size: 28px;
                font-weight: bold;
                color: {COLORS['text_muted']};
                padding: 8px 16px;
                border: 2px solid {COLORS['border']};
                border-radius: 8px;
                background-color: {COLORS['bg_medium']};
            """)


class ConvertWidget(QWidget):
    """Simplified widget for PDF conversion with optional sanitization."""
    
    status_message = Signal(str)
    
    LANGUAGES = [
        ("Dutch (nl)", "nl"),
        ("English (en)", "en"),
        ("German (de)", "de"),
        ("French (fr)", "fr"),
        ("Italian (it)", "it"),
        ("Spanish (es)", "es"),
    ]
    
    def __init__(self):
        super().__init__()
        self.current_pdf = None
        self.current_output = None
        self.current_mapping = None
        self.worker = None
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the convert widget UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        
        # Drop zone
        self.drop_zone = DropZone()
        self.drop_zone.file_dropped.connect(self.on_file_dropped)
        layout.addWidget(self.drop_zone)
        
        # Language selector (for sanitization)
        lang_layout = QHBoxLayout()
        lang_layout.addWidget(QLabel("Language (for sanitization):"))
        self.language_combo = QComboBox()
        for name, code in self.LANGUAGES:
            self.language_combo.addItem(name, code)
        lang_layout.addWidget(self.language_combo)
        lang_layout.addStretch()
        layout.addLayout(lang_layout)
        
        # Big action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(20)
        
        # Convert button (non-confidential) - uses accent color
        self.convert_btn = QPushButton("Just Convert\nPDF to Text")
        self.convert_btn.setMinimumHeight(80)
        self.convert_btn.setStyleSheet(f"""
            QPushButton {{
                font-size: 15px;
                font-weight: bold;
                background-color: {COLORS['bg_light']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['border']};
                border-radius: 10px;
                padding: 15px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent']};
                color: {COLORS['bg_dark']};
                border-color: {COLORS['accent']};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_medium']};
                color: {COLORS['text_muted']};
                border-color: {COLORS['bg_medium']};
            }}
        """)
        self.convert_btn.clicked.connect(lambda: self.start_conversion(sanitize=False))
        self.convert_btn.setEnabled(False)
        button_layout.addWidget(self.convert_btn)

        # Convert & Sanitize button (confidential) - amber/gold accent
        self.sanitize_btn = QPushButton("Convert + Sanitize\nFor Confidential Files")
        self.sanitize_btn.setMinimumHeight(80)
        self.sanitize_btn.setStyleSheet(f"""
            QPushButton {{
                font-size: 15px;
                font-weight: bold;
                background-color: {COLORS['accent']};
                color: {COLORS['bg_dark']};
                border: 2px solid {COLORS['accent']};
                border-radius: 10px;
                padding: 15px;
            }}
            QPushButton:hover {{
                background-color: #f5b82e;
                border-color: #f5b82e;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_medium']};
                color: {COLORS['text_muted']};
                border-color: {COLORS['bg_medium']};
            }}
        """)
        self.sanitize_btn.clicked.connect(lambda: self.start_conversion(sanitize=True))
        self.sanitize_btn.setEnabled(False)
        button_layout.addWidget(self.sanitize_btn)
        
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        layout.addWidget(self.progress_bar)
        
        # Results section
        self.results_group = QGroupBox("Results")
        self.results_group.setVisible(False)
        results_layout = QVBoxLayout(self.results_group)
        
        # Stats
        self.stats_label = QLabel("")
        self.stats_label.setStyleSheet("font-size: 13px;")
        results_layout.addWidget(self.stats_label)
        
        # Output preview
        self.output_preview = QTextEdit()
        self.output_preview.setReadOnly(True)
        self.output_preview.setMaximumHeight(200)
        self.output_preview.setPlaceholderText("Output preview...")
        results_layout.addWidget(self.output_preview)
        
        # Action buttons for results
        result_buttons = QHBoxLayout()
        
        self.open_finder_btn = QPushButton("Open in Finder")
        self.open_finder_btn.clicked.connect(self.open_in_finder)
        result_buttons.addWidget(self.open_finder_btn)
        
        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        result_buttons.addWidget(self.copy_btn)
        
        self.gdrive_btn = QPushButton("Upload to Google Drive")
        self.gdrive_btn.clicked.connect(self.upload_to_gdrive)
        result_buttons.addWidget(self.gdrive_btn)
        
        result_buttons.addStretch()
        
        self.save_mapping_btn = QPushButton("Save Mapping...")
        self.save_mapping_btn.setVisible(False)
        self.save_mapping_btn.clicked.connect(self.save_mapping)
        result_buttons.addWidget(self.save_mapping_btn)
        
        results_layout.addLayout(result_buttons)
        layout.addWidget(self.results_group)
        
        layout.addStretch()
    
    def on_file_dropped(self, file_path):
        """Handle file drop or browse click."""
        if not file_path:
            # Open file dialog
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select PDF File",
                "",
                "PDF Files (*.pdf);;All Files (*)"
            )
        
        if file_path and file_path.lower().endswith('.pdf'):
            self.current_pdf = file_path
            self.drop_zone.set_file(file_path)
            self.convert_btn.setEnabled(True)
            self.sanitize_btn.setEnabled(True)
            self.status_message.emit(f"Selected: {os.path.basename(file_path)}")
    
    def start_conversion(self, sanitize=False):
        """Start the PDF conversion process."""
        if not self.current_pdf:
            return
        
        # Get output directory (same as PDF)
        output_dir = os.path.dirname(self.current_pdf)
        language = self.language_combo.currentData()
        
        # Disable UI during conversion
        self.convert_btn.setEnabled(False)
        self.sanitize_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.results_group.setVisible(False)
        
        mode = "Converting & sanitizing" if sanitize else "Converting"
        self.status_message.emit(f"{mode} PDF...")
        
        # Start worker thread
        self.worker = ConvertWorker(self.current_pdf, output_dir, sanitize, language)
        self.worker.finished.connect(self.on_conversion_finished)
        self.worker.error.connect(self.on_conversion_error)
        self.worker.progress.connect(self.status_message.emit)
        self.worker.start()
    
    def on_conversion_finished(self, text, metadata, mapping):
        """Handle successful conversion."""
        self.current_output = text
        self.current_mapping = mapping
        
        # Calculate stats
        pdf_path = Path(self.current_pdf)
        pdf_size_bytes = pdf_path.stat().st_size
        text_size_bytes = len(text.encode('utf-8'))
        reduction = ((pdf_size_bytes - text_size_bytes) / pdf_size_bytes) * 100 if pdf_size_bytes > 0 else 0
        
        # Format sizes appropriately (KB for small, MB for large)
        def format_size(size_bytes):
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.1f} KB"
            else:
                return f"{size_bytes / (1024 * 1024):.1f} MB"
        
        stats = f"<b>Conversion complete!</b><br>"
        stats += f"PDF: {format_size(pdf_size_bytes)} → Text: {format_size(text_size_bytes)} ({reduction:.0f}% smaller)<br>"
        
        if 'total_pages' in metadata:
            stats += f"Pages: {metadata['total_pages']}"
            if metadata.get('ocr_pages', 0) > 0:
                stats += f" ({metadata['ocr_pages']} OCR)"
            stats += "<br>"
        
        stats += f"Characters: {len(text):,}<br>"
        
        if mapping:
            entities = len(mapping.entries) if hasattr(mapping, 'entries') else 0
            stats += f"<b>Entities sanitized: {entities}</b><br>"
            output_file = metadata.get('output_file', 'N/A')
            mapping_file = metadata.get('mapping_file', '')
            stats += f"Output: {output_file}<br>"
            if mapping_file:
                stats += f"Mapping: {mapping_file}"
        else:
            output_file = metadata.get('output_file', '')
            if output_file:
                stats += f"Output: {output_file}"
        
        self.stats_label.setText(stats)
        
        # Show preview (first 2000 chars)
        preview = text[:2000]
        if len(text) > 2000:
            preview += "\n\n... (truncated)"
        self.output_preview.setPlainText(preview)
        
        # Show/hide mapping button
        self.save_mapping_btn.setVisible(mapping is not None)
        
        # Reset UI
        self.convert_btn.setEnabled(True)
        self.sanitize_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.results_group.setVisible(True)
        
        self.status_message.emit("Conversion complete!")
    
    def on_conversion_error(self, error_msg):
        """Handle conversion error."""
        self.convert_btn.setEnabled(True)
        self.sanitize_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_message.emit("Conversion failed")
        QMessageBox.critical(self, "Conversion Error", f"Failed to convert PDF:\n{error_msg}")
    
    def open_in_finder(self):
        """Open the output directory in Finder."""
        if self.current_pdf:
            output_dir = os.path.dirname(self.current_pdf)
            import subprocess
            subprocess.run(['open', output_dir])
    
    def copy_to_clipboard(self):
        """Copy the output text to clipboard."""
        if self.current_output:
            try:
                from PySide6.QtWidgets import QApplication
            except ImportError:
                from PyQt6.QtWidgets import QApplication
            
            clipboard = QApplication.clipboard()
            clipboard.setText(self.current_output)
            self.status_message.emit("Copied to clipboard!")
    
    def upload_to_gdrive(self):
        """Upload the output to Google Drive."""
        if not self.current_output:
            return
        
        try:
            from aiwhisperer.gui.google_drive import upload_to_drive, is_authenticated
            
            if not is_authenticated():
                reply = QMessageBox.question(
                    self,
                    "Google Drive Authentication",
                    "You need to authenticate with Google Drive.\n\n"
                    "This will open a browser window for you to sign in.\n\n"
                    "Continue?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
            
            # Get filename
            pdf_name = os.path.basename(self.current_pdf)
            base_name = os.path.splitext(pdf_name)[0]
            if self.current_mapping:
                filename = f"{base_name}_sanitized.txt"
            else:
                filename = f"{base_name}.txt"
            
            self.status_message.emit("Uploading to Google Drive...")
            
            # Upload
            file_id = upload_to_drive(self.current_output, filename)
            
            if file_id:
                self.status_message.emit(f"Uploaded to Google Drive: {filename}")
                QMessageBox.information(
                    self,
                    "Upload Complete",
                    f"File uploaded to Google Drive:\n{filename}\n\n"
                    "You can now use it with NotebookLM or other AI tools."
                )
            else:
                raise Exception("Upload returned no file ID")
                
        except ImportError:
            QMessageBox.warning(
                self,
                "Google Drive Not Available",
                "Google Drive integration is not installed.\n\n"
                "Install with: pip install google-api-python-client google-auth-oauthlib"
            )
        except Exception as e:
            QMessageBox.critical(self, "Upload Error", f"Failed to upload:\n{e}")
    
    def save_mapping(self):
        """Save the mapping file."""
        if not self.current_mapping:
            return
        
        # Suggest filename
        pdf_name = os.path.basename(self.current_pdf)
        base_name = os.path.splitext(pdf_name)[0]
        suggested_name = f"{base_name}_mapping.json"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Mapping File",
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
        return False  # Convert widget doesn't track unsaved changes
    
    def apply_settings(self, settings):
        """Apply settings from QSettings."""
        default_lang = settings.value("default_language", "nl")
        for i in range(self.language_combo.count()):
            if self.language_combo.itemData(i) == default_lang:
                self.language_combo.setCurrentIndex(i)
                break
