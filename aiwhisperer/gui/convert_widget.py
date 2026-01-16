"""
AIWhisperer GUI - Convert Widget

Complete PDF-to-text conversion with optional sanitization.
Implements the full Digital Digging workflow.
"""

import os
import webbrowser
from pathlib import Path

# Try PySide6 first, fall back to PyQt6
try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QTextEdit, QPushButton, QComboBox, QCheckBox,
        QFileDialog, QGroupBox, QProgressBar, QFrame,
        QMessageBox, QSizePolicy, QScrollArea, QApplication
    )
    from PySide6.QtCore import Qt, Signal, QThread, QMimeData
    from PySide6.QtGui import QDragEnterEvent, QDropEvent, QFont, QCursor
except ImportError:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QTextEdit, QPushButton, QComboBox, QCheckBox,
        QFileDialog, QGroupBox, QProgressBar, QFrame,
        QMessageBox, QSizePolicy, QScrollArea, QApplication
    )
    from PyQt6.QtCore import Qt, pyqtSignal as Signal, QThread, QMimeData
    from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QFont, QCursor


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
    'warning': '#fbbf24',
}

# Prompt templates for NotebookLM
PROMPT_TEMPLATES = [
    {
        "name": "Timeline",
        "prompt": "Give me a prompt I can use to create a comprehensive chronological timeline from these documents, including all dates, events, and people involved."
    },
    {
        "name": "Connections",
        "prompt": "Analyze all relationships and connections between people mentioned in these documents. Who communicated with whom? Who is connected to whom and how?"
    },
    {
        "name": "Financial",
        "prompt": "Extract all financial transactions, amounts, bank accounts, and money flows mentioned in these documents. Create a structured list with dates and parties involved."
    },
    {
        "name": "Summary",
        "prompt": "Create a comprehensive executive summary of these documents. What are the key findings, main events, and most important conclusions?"
    },
]


class ConvertWorker(QThread):
    """Background worker for PDF conversion operations."""

    finished = Signal(str, dict, object)  # text, metadata, mapping (or None)
    error = Signal(str)
    progress = Signal(str)
    page_progress = Signal(int, int)  # current, total

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

            def progress_callback(current, total, msg):
                self.page_progress.emit(current, total)
                self.progress.emit(msg)

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


class PipelineIndicator(QFrame):
    """Visual pipeline showing current step."""

    STEPS = ["PDF", "Convert", "Sanitize", "Upload", "Decode"]

    def __init__(self):
        super().__init__()
        self.current_step = 0
        self.setup_ui()

    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(4)

        self.step_labels = []

        for i, step in enumerate(self.STEPS):
            # Step label
            label = QLabel(step)
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label.setStyleSheet(f"""
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 500;
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_muted']};
                border: 1px solid {COLORS['border']};
            """)
            self.step_labels.append(label)
            layout.addWidget(label)

            # Arrow between steps
            if i < len(self.STEPS) - 1:
                arrow = QLabel(">")
                arrow.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 14px;")
                layout.addWidget(arrow)

        layout.addStretch()
        self.set_step(0)

    def set_step(self, step_index):
        self.current_step = step_index
        for i, label in enumerate(self.step_labels):
            if i < step_index:
                # Completed
                label.setStyleSheet(f"""
                    padding: 6px 12px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: 500;
                    background-color: {COLORS['success']};
                    color: {COLORS['bg_dark']};
                    border: 1px solid {COLORS['success']};
                """)
            elif i == step_index:
                # Current
                label.setStyleSheet(f"""
                    padding: 6px 12px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: 600;
                    background-color: {COLORS['accent']};
                    color: {COLORS['bg_dark']};
                    border: 1px solid {COLORS['accent']};
                """)
            else:
                # Future
                label.setStyleSheet(f"""
                    padding: 6px 12px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: 500;
                    background-color: {COLORS['bg_dark']};
                    color: {COLORS['text_muted']};
                    border: 1px solid {COLORS['border']};
                """)


class DropZone(QFrame):
    """Drag-and-drop zone for PDF files."""

    file_dropped = Signal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        self.setMinimumHeight(160)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._apply_default_style()

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)

        self.icon_label = QLabel("PDF")
        self.icon_label.setStyleSheet(f"""
            font-size: 24px;
            font-weight: bold;
            color: {COLORS['text_muted']};
            padding: 6px 14px;
            border: 2px solid {COLORS['border']};
            border-radius: 6px;
            background-color: {COLORS['bg_medium']};
        """)
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.icon_label)

        self.text_label = QLabel("Drop PDF here or click to browse")
        self.text_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px;")
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
                border-radius: 10px;
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
                        border-radius: 10px;
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

    def set_file(self, file_path, page_count=None):
        if file_path:
            self.file_label.setText(os.path.basename(file_path))
            self.text_label.setText("PDF selected:")
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            size_text = f"{size_mb:.1f} MB"
            if page_count:
                size_text += f" | {page_count:,} pages"
            self.size_label.setText(size_text)
            self.icon_label.setText("OK")
            self.icon_label.setStyleSheet(f"""
                font-size: 24px;
                font-weight: bold;
                color: {COLORS['success']};
                padding: 6px 14px;
                border: 2px solid {COLORS['success']};
                border-radius: 6px;
                background-color: {COLORS['bg_medium']};
            """)
        else:
            self.file_label.setText("")
            self.size_label.setText("")
            self.text_label.setText("Drop PDF here or click to browse")
            self.icon_label.setText("PDF")
            self.icon_label.setStyleSheet(f"""
                font-size: 24px;
                font-weight: bold;
                color: {COLORS['text_muted']};
                padding: 6px 14px;
                border: 2px solid {COLORS['border']};
                border-radius: 6px;
                background-color: {COLORS['bg_medium']};
            """)


class ConvertWidget(QWidget):
    """Complete widget for PDF conversion with all Digital Digging features."""

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
        self.pdf_page_count = None
        self.setup_ui()

    def setup_ui(self):
        """Set up the convert widget UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 0, 0)

        # Pipeline indicator
        self.pipeline = PipelineIndicator()
        layout.addWidget(self.pipeline)

        # Drop zone
        self.drop_zone = DropZone()
        self.drop_zone.file_dropped.connect(self.on_file_dropped)
        layout.addWidget(self.drop_zone)

        # Split warning (hidden by default)
        self.split_warning = QLabel("")
        self.split_warning.setStyleSheet(f"""
            background-color: {COLORS['bg_light']};
            color: {COLORS['warning']};
            padding: 10px;
            border-radius: 6px;
            font-size: 12px;
        """)
        self.split_warning.setVisible(False)
        layout.addWidget(self.split_warning)

        # Options row
        options_layout = QHBoxLayout()

        # Language selector
        options_layout.addWidget(QLabel("Language:"))
        self.language_combo = QComboBox()
        self.language_combo.setMinimumWidth(120)
        for name, code in self.LANGUAGES:
            self.language_combo.addItem(name, code)
        options_layout.addWidget(self.language_combo)

        options_layout.addStretch()

        # Time saved estimate
        self.time_estimate = QLabel("")
        self.time_estimate.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px;")
        options_layout.addWidget(self.time_estimate)

        layout.addLayout(options_layout)

        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(16)

        self.convert_btn = QPushButton("Just Convert\nPDF to Text")
        self.convert_btn.setMinimumHeight(70)
        self.convert_btn.setStyleSheet(f"""
            QPushButton {{
                font-size: 14px;
                font-weight: bold;
                background-color: {COLORS['bg_light']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['border']};
                border-radius: 8px;
                padding: 12px;
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

        self.sanitize_btn = QPushButton("Convert + Sanitize\nFor Confidential Files")
        self.sanitize_btn.setMinimumHeight(70)
        self.sanitize_btn.setStyleSheet(f"""
            QPushButton {{
                font-size: 14px;
                font-weight: bold;
                background-color: {COLORS['accent']};
                color: {COLORS['bg_dark']};
                border: 2px solid {COLORS['accent']};
                border-radius: 8px;
                padding: 12px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
                border-color: {COLORS['accent_hover']};
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

        # Progress section
        self.progress_section = QFrame()
        self.progress_section.setVisible(False)
        progress_layout = QVBoxLayout(self.progress_section)
        progress_layout.setContentsMargins(0, 0, 0, 0)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        progress_layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        progress_layout.addWidget(self.progress_label)

        layout.addWidget(self.progress_section)

        # Results section
        self.results_section = QFrame()
        self.results_section.setVisible(False)
        self.results_section.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_dark']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        results_layout = QVBoxLayout(self.results_section)

        # Compression stats (prominent!)
        self.stats_frame = QFrame()
        self.stats_frame.setStyleSheet(f"""
            background-color: {COLORS['bg_light']};
            border-radius: 6px;
            padding: 12px;
        """)
        stats_layout = QVBoxLayout(self.stats_frame)

        self.compression_label = QLabel("")
        self.compression_label.setStyleSheet(f"""
            font-size: 18px;
            font-weight: bold;
            color: {COLORS['success']};
        """)
        self.compression_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        stats_layout.addWidget(self.compression_label)

        self.stats_detail = QLabel("")
        self.stats_detail.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        self.stats_detail.setAlignment(Qt.AlignmentFlag.AlignCenter)
        stats_layout.addWidget(self.stats_detail)

        results_layout.addWidget(self.stats_frame)

        # Entity preview (for sanitized files)
        self.entity_preview = QGroupBox("Entities Replaced")
        self.entity_preview.setVisible(False)
        entity_layout = QVBoxLayout(self.entity_preview)

        self.entity_list = QLabel("")
        self.entity_list.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        self.entity_list.setWordWrap(True)
        entity_layout.addWidget(self.entity_list)

        results_layout.addWidget(self.entity_preview)

        # Warning about review
        self.review_warning = QLabel(
            "IMPORTANT: Review the sanitized output before uploading. "
            "Context clues may still identify people."
        )
        self.review_warning.setStyleSheet(f"""
            background-color: {COLORS['bg_medium']};
            color: {COLORS['warning']};
            padding: 8px;
            border-radius: 4px;
            font-size: 11px;
        """)
        self.review_warning.setWordWrap(True)
        self.review_warning.setVisible(False)
        results_layout.addWidget(self.review_warning)

        # Output preview
        self.output_preview = QTextEdit()
        self.output_preview.setReadOnly(True)
        self.output_preview.setMaximumHeight(150)
        self.output_preview.setStyleSheet(f"""
            background-color: {COLORS['bg_medium']};
            color: {COLORS['text_primary']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
            font-family: monospace;
            font-size: 11px;
        """)
        results_layout.addWidget(self.output_preview)

        # Action buttons row 1
        action_row1 = QHBoxLayout()

        self.open_finder_btn = QPushButton("Open in Finder")
        self.open_finder_btn.clicked.connect(self.open_in_finder)
        action_row1.addWidget(self.open_finder_btn)

        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        action_row1.addWidget(self.copy_btn)

        self.notebooklm_btn = QPushButton("Open NotebookLM")
        self.notebooklm_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: {COLORS['bg_dark']};
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        self.notebooklm_btn.clicked.connect(self.open_notebooklm)
        action_row1.addWidget(self.notebooklm_btn)

        results_layout.addLayout(action_row1)

        # Prompt templates section
        prompt_group = QGroupBox("Prompt Templates for AI")
        prompt_layout = QHBoxLayout(prompt_group)

        for template in PROMPT_TEMPLATES:
            btn = QPushButton(template["name"])
            btn.setToolTip(template["prompt"][:100] + "...")
            btn.clicked.connect(lambda checked, p=template["prompt"]: self.copy_prompt(p))
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS['bg_light']};
                    padding: 6px 12px;
                    font-size: 11px;
                }}
            """)
            prompt_layout.addWidget(btn)

        prompt_layout.addStretch()
        results_layout.addWidget(prompt_group)

        layout.addWidget(self.results_section)

        # Footer
        footer = QLabel(
            '<a href="https://www.digitaldigging.org/p/speed-reading-a-massive-criminal" '
            f'style="color: {COLORS["text_muted"]};">Read the full story on Digital Digging</a>'
        )
        footer.setOpenExternalLinks(True)
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet(f"font-size: 11px; color: {COLORS['text_muted']}; padding: 8px;")
        layout.addWidget(footer)

        layout.addStretch()

    def on_file_dropped(self, file_path):
        """Handle file drop or browse click."""
        if not file_path:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select PDF File",
                "",
                "PDF Files (*.pdf);;All Files (*)"
            )

        if file_path and file_path.lower().endswith('.pdf'):
            self.current_pdf = file_path

            # Get PDF info
            try:
                from aiwhisperer.converter import get_pdf_info
                info = get_pdf_info(file_path)
                self.pdf_page_count = info.get('pages')
            except Exception:
                self.pdf_page_count = None

            self.drop_zone.set_file(file_path, self.pdf_page_count)
            self.convert_btn.setEnabled(True)
            self.sanitize_btn.setEnabled(True)
            self.pipeline.set_step(0)

            # Show split warning for large files
            if self.pdf_page_count and self.pdf_page_count > 500:
                parts = (self.pdf_page_count // 500) + 1
                self.split_warning.setText(
                    f"Large file: {self.pdf_page_count:,} pages. "
                    f"Consider using CLI with --split to create {parts} parts of ~500 pages each."
                )
                self.split_warning.setVisible(True)
            else:
                self.split_warning.setVisible(False)

            # Time saved estimate
            if self.pdf_page_count:
                # Rough estimate: 1 page = 1 minute manual, 0.01 minute with AI
                manual_hours = self.pdf_page_count / 60
                self.time_estimate.setText(
                    f"Manual: ~{manual_hours:.0f}h | With AI: ~{self.pdf_page_count * 0.01:.0f}min"
                )
            else:
                self.time_estimate.setText("")

            self.status_message.emit(f"Selected: {os.path.basename(file_path)}")

    def start_conversion(self, sanitize=False):
        """Start the PDF conversion process."""
        if not self.current_pdf:
            return

        output_dir = os.path.dirname(self.current_pdf)
        language = self.language_combo.currentData()

        # Update UI
        self.convert_btn.setEnabled(False)
        self.sanitize_btn.setEnabled(False)
        self.progress_section.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.results_section.setVisible(False)
        self.pipeline.set_step(1 if not sanitize else 2)

        mode = "Converting + sanitizing" if sanitize else "Converting"
        self.status_message.emit(f"{mode} PDF...")
        self.progress_label.setText(f"{mode}...")

        # Start worker
        self.worker = ConvertWorker(self.current_pdf, output_dir, sanitize, language)
        self.worker.finished.connect(self.on_conversion_finished)
        self.worker.error.connect(self.on_conversion_error)
        self.worker.progress.connect(self.on_progress)
        self.worker.page_progress.connect(self.on_page_progress)
        self.worker.start()

    def on_progress(self, message):
        self.progress_label.setText(message)
        self.status_message.emit(message)

    def on_page_progress(self, current, total):
        if total > 0:
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(current)

    def on_conversion_finished(self, text, metadata, mapping):
        """Handle successful conversion."""
        self.current_output = text
        self.current_mapping = mapping

        # Calculate compression stats
        pdf_path = Path(self.current_pdf)
        pdf_size = pdf_path.stat().st_size
        text_size = len(text.encode('utf-8'))
        reduction = ((pdf_size - text_size) / pdf_size) * 100 if pdf_size > 0 else 0

        def format_size(size):
            if size < 1024:
                return f"{size} B"
            elif size < 1024 * 1024:
                return f"{size / 1024:.1f} KB"
            else:
                return f"{size / (1024 * 1024):.1f} MB"

        # Big compression display
        self.compression_label.setText(
            f"{format_size(pdf_size)} → {format_size(text_size)} ({reduction:.0f}% smaller)"
        )

        # Details
        details = []
        if 'total_pages' in metadata:
            pages_str = f"{metadata['total_pages']} pages"
            if metadata.get('ocr_pages', 0) > 0:
                pages_str += f" ({metadata['ocr_pages']} OCR)"
            if metadata.get('failed_pages', 0) > 0:
                pages_str += f" ({metadata['failed_pages']} failed)"
            details.append(pages_str)
        details.append(f"{len(text):,} characters")
        self.stats_detail.setText(" | ".join(details))

        # Entity preview for sanitized files
        if mapping and hasattr(mapping, 'entries'):
            self.entity_preview.setVisible(True)
            self.review_warning.setVisible(True)

            entities = mapping.entries
            entity_count = len(entities)

            # Group by category
            by_category = {}
            for placeholder, entry in list(entities.items())[:20]:
                cat = placeholder.split('_')[0] if '_' in placeholder else 'OTHER'
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(f"{entry.canonical} → {placeholder}")

            preview_lines = [f"Total: {entity_count} unique entities replaced"]
            for cat, items in list(by_category.items())[:5]:
                preview_lines.append(f"\n{cat}: " + ", ".join(items[:3]))
                if len(items) > 3:
                    preview_lines.append(f"  ...and {len(items) - 3} more")

            self.entity_list.setText("\n".join(preview_lines))
        else:
            self.entity_preview.setVisible(False)
            self.review_warning.setVisible(False)

        # Output preview
        preview = text[:1500]
        if len(text) > 1500:
            preview += "\n\n... (truncated)"
        self.output_preview.setPlainText(preview)

        # Update UI
        self.convert_btn.setEnabled(True)
        self.sanitize_btn.setEnabled(True)
        self.progress_section.setVisible(False)
        self.results_section.setVisible(True)
        self.pipeline.set_step(3)

        self.status_message.emit("Conversion complete!")

    def on_conversion_error(self, error_msg):
        """Handle conversion error."""
        self.convert_btn.setEnabled(True)
        self.sanitize_btn.setEnabled(True)
        self.progress_section.setVisible(False)
        self.pipeline.set_step(0)
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
            clipboard = QApplication.clipboard()
            clipboard.setText(self.current_output)
            self.status_message.emit("Copied to clipboard!")

    def open_notebooklm(self):
        """Open NotebookLM in browser."""
        webbrowser.open("https://notebooklm.google.com/")
        self.status_message.emit("Opened NotebookLM - upload your file there")

    def copy_prompt(self, prompt):
        """Copy a prompt template to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(prompt)
        self.status_message.emit("Prompt copied! Paste it in NotebookLM.")

    def has_unsaved_changes(self):
        """Check if there are unsaved changes."""
        return False

    def apply_settings(self, settings):
        """Apply settings from QSettings."""
        default_lang = settings.value("default_language", "nl")
        for i in range(self.language_combo.count()):
            if self.language_combo.itemData(i) == default_lang:
                self.language_combo.setCurrentIndex(i)
                break
