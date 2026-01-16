# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for AIWhisperer macOS build.

This creates a standalone macOS executable that can be distributed
without requiring users to install Python or dependencies.

Build with:
    pyinstaller packaging/macos/aiwhisperer.spec
"""

import sys
from pathlib import Path

# Get the project root directory
project_root = Path(SPECPATH).parent.parent.parent

block_cipher = None

# Hidden imports for optional dependencies
# These are imported dynamically and PyInstaller may not detect them
hidden_imports = [
    # Click and CLI
    'click',
    'click.core',
    'click.decorators',
    'click.exceptions',
    'click.formatting',
    'click.parser',
    'click.termui',
    'click.testing',
    'click.types',
    'click.utils',
    
    # Core aiwhisperer modules
    'aiwhisperer',
    'aiwhisperer.cli',
    'aiwhisperer.encoder',
    'aiwhisperer.decoder',
    'aiwhisperer.mapper',
    'aiwhisperer.converter',
    'aiwhisperer.strategies',
    'aiwhisperer.detectors',
    'aiwhisperer.detectors.hybrid',
    'aiwhisperer.detectors.patterns',
    'aiwhisperer.detectors.ner',
    'aiwhisperer.detectors.presidio_detector',
    'aiwhisperer.detectors.gliner_detector',
    
    # YAML for config
    'yaml',
    
    # Regex
    'regex',
    
    # Optional: spaCy (if installed)
    'spacy',
    'spacy.lang.nl',
    'spacy.lang.en',
    'spacy.lang.de',
    'spacy.lang.fr',
    'spacy.lang.it',
    'spacy.lang.es',
    
    # Optional: PDF conversion
    'fitz',  # PyMuPDF
    'pytesseract',
    'pdf2image',
    
    # Standard library modules that might be needed
    'json',
    'pathlib',
    'datetime',
    'hashlib',
    'platform',
    'typing',
    'dataclasses',
    'collections',
    're',
]

# Collect data files
datas = [
    # Include the aiwhisperer package
    (str(project_root / 'aiwhisperer'), 'aiwhisperer'),
]

# Analysis
a = Analysis(
    [str(project_root / 'aiwhisperer' / 'cli.py')],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude heavy optional dependencies that users can install separately
        'torch',
        'tensorflow',
        'transformers',
        'marker',
        'surya',
        'gliner',
        'presidio_analyzer',
        'presidio_anonymizer',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='aiwhisperer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # CLI tool needs console
    disable_windowed_traceback=False,
    argv_emulation=True,  # Important for macOS CLI tools
    target_arch=None,  # Build for current architecture
    codesign_identity=None,
    entitlements_file=None,
    icon=str(project_root / 'packaging' / 'macos' / 'icon.icns') if (project_root / 'packaging' / 'macos' / 'icon.icns').exists() else None,
)
