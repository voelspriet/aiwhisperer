"""
AIWhisperer GUI - Dependency Checker

This module provides functionality to check and report on available dependencies.
"""

import sys
import importlib


def check_all_dependencies():
    """Check all dependencies and return a formatted report."""
    lines = []
    
    # Python version
    lines.append(f"Python Version: {sys.version}")
    lines.append("")
    
    # Core dependencies
    lines.append("=== Core Dependencies ===")
    
    core_deps = [
        ("click", "CLI framework"),
        ("yaml", "YAML parsing (pyyaml)"),
        ("regex", "Advanced regex"),
    ]
    
    for module, desc in core_deps:
        status = check_module(module)
        lines.append(f"  {desc}: {status}")
    
    lines.append("")
    
    # GUI dependencies
    lines.append("=== GUI Dependencies ===")
    
    gui_status = "Not installed"
    try:
        import PySide6
        gui_status = f"PySide6 {PySide6.__version__}"
    except ImportError:
        try:
            import PyQt6
            from PyQt6.QtCore import PYQT_VERSION_STR
            gui_status = f"PyQt6 {PYQT_VERSION_STR}"
        except ImportError:
            pass
    
    lines.append(f"  Qt Bindings: {gui_status}")
    lines.append("")
    
    # NLP dependencies
    lines.append("=== NLP Dependencies ===")
    
    # spaCy
    spacy_status = check_module("spacy")
    lines.append(f"  spaCy: {spacy_status}")
    
    if "installed" in spacy_status.lower():
        # Check for language models
        lines.append("  Language Models:")
        models = [
            ("nl_core_news_sm", "Dutch"),
            ("en_core_web_sm", "English"),
            ("de_core_news_sm", "German"),
            ("fr_core_news_sm", "French"),
            ("it_core_news_sm", "Italian"),
            ("es_core_news_sm", "Spanish"),
        ]
        
        import spacy
        for model_name, lang in models:
            try:
                spacy.load(model_name)
                lines.append(f"    {lang} ({model_name}): Installed")
            except OSError:
                lines.append(f"    {lang} ({model_name}): Not installed")
                lines.append(f"      Install with: python -m spacy download {model_name}")
    
    # Presidio
    presidio_status = check_module("presidio_analyzer")
    lines.append(f"  Presidio: {presidio_status}")
    
    # GLiNER
    gliner_status = check_module("gliner")
    lines.append(f"  GLiNER: {gliner_status}")
    
    lines.append("")
    
    # PDF conversion dependencies
    lines.append("=== PDF Conversion Dependencies ===")
    
    # marker-pdf
    marker_status = check_module("marker")
    lines.append(f"  marker-pdf: {marker_status}")
    
    # PyMuPDF
    pymupdf_status = check_module("fitz")
    lines.append(f"  PyMuPDF (fitz): {pymupdf_status}")
    
    # pytesseract
    tesseract_status = check_module("pytesseract")
    lines.append(f"  pytesseract: {tesseract_status}")
    
    # pdf2image
    pdf2image_status = check_module("pdf2image")
    lines.append(f"  pdf2image: {pdf2image_status}")
    
    lines.append("")
    
    # Installation suggestions
    lines.append("=== Installation Commands ===")
    lines.append("  Basic: pip install aiwhisperer")
    lines.append("  With spaCy: pip install aiwhisperer[spacy]")
    lines.append("  With OCR: pip install aiwhisperer[ocr]")
    lines.append("  Full: pip install aiwhisperer[all]")
    lines.append("")
    lines.append("  GUI: pip install PySide6")
    
    return "\n".join(lines)


def check_module(module_name):
    """Check if a module is installed and return its version if available."""
    try:
        mod = importlib.import_module(module_name)
        version = getattr(mod, "__version__", None)
        if version:
            return f"Installed (v{version})"
        return "Installed"
    except ImportError:
        return "Not installed"


def get_available_backends():
    """Get list of available detection backends."""
    backends = ["patterns"]  # Always available
    
    try:
        import spacy
        backends.append("spacy")
        backends.append("hybrid")
    except ImportError:
        pass
    
    try:
        import presidio_analyzer
        backends.append("presidio")
    except ImportError:
        pass
    
    try:
        import gliner
        backends.append("gliner")
    except ImportError:
        pass
    
    return backends


def get_available_converters():
    """Get list of available PDF converters."""
    converters = []
    
    try:
        import marker
        converters.append("marker")
    except ImportError:
        pass
    
    try:
        import pytesseract
        import pdf2image
        converters.append("tesseract")
    except ImportError:
        pass
    
    try:
        import fitz
        converters.append("pymupdf")
    except ImportError:
        pass
    
    return converters
