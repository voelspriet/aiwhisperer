# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for AIWhisperer GUI macOS application.

This creates a standalone .app bundle for macOS with the full GUI interface.

Usage:
    pyinstaller packaging/macos/aiwhisperer_gui.spec --clean --noconfirm

The resulting .app bundle will be in dist/AIWhisperer.app
"""

from pathlib import Path
import sys

# Get the project root directory
# SPECPATH is the directory containing this spec file (packaging/macos/)
# So we need to go up 2 levels to reach the project root
project_root = Path(SPECPATH).parent.parent

# Version extraction
version = "0.4.0"
try:
    setup_py = project_root / "setup.py"
    if setup_py.exists():
        content = setup_py.read_text()
        import re
        match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
        if match:
            version = match.group(1)
except Exception:
    pass

print(f"Building AIWhisperer GUI v{version}")
print(f"Project root: {project_root}")

# Hidden imports for dynamic modules
hidden_imports = [
    # Qt/PySide6 imports
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtWidgets',
    
    # Click CLI (needed for some internal imports)
    'click',
    'click.testing',
    
    # AIWhisperer modules
    'aiwhisperer',
    'aiwhisperer.cli',
    'aiwhisperer.encoder',
    'aiwhisperer.decoder',
    'aiwhisperer.mapper',
    'aiwhisperer.strategies',
    'aiwhisperer.detectors',
    'aiwhisperer.detectors.patterns',
    'aiwhisperer.detectors.hybrid',
    'aiwhisperer.detectors.ner',
    'aiwhisperer.gui',
    'aiwhisperer.gui.main',
    'aiwhisperer.gui.main_window',
    'aiwhisperer.gui.convert_widget',
    'aiwhisperer.gui.encode_widget',
    'aiwhisperer.gui.decode_widget',
    'aiwhisperer.gui.settings_dialog',
    'aiwhisperer.gui.dependency_checker',
    'aiwhisperer.gui.google_drive',
    'aiwhisperer.converter',
    
    # Google Drive API (optional)
    'googleapiclient',
    'googleapiclient.discovery',
    'googleapiclient.http',
    'google.oauth2.credentials',
    'google_auth_oauthlib.flow',
    'google.auth.transport.requests',
    
    # spaCy (optional but commonly used)
    'spacy',
    'spacy.lang.nl',
    'spacy.lang.en',
    'spacy.lang.de',
    'spacy.lang.fr',
    'spacy.lang.it',
    'spacy.lang.es',
    
    # Other dependencies
    'yaml',
    'regex',
]

# Exclude heavy optional dependencies to keep bundle size reasonable
excludes = [
    'torch',
    'tensorflow',
    'transformers',
    'marker',
    'surya',
    'gliner',
    'presidio_analyzer',
    'presidio_anonymizer',
    'matplotlib',
    'scipy',
    'pandas',
    'numpy.testing',
]

# Data files to include
datas = [
    # Include the aiwhisperer package
    (str(project_root / 'aiwhisperer'), 'aiwhisperer'),
]

# Analysis
a = Analysis(
    [str(Path(SPECPATH) / 'gui_entry_point.py')],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

# Remove duplicate files
pyz = PYZ(a.pure)

# Create the executable
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AIWhisperer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # No console window for GUI app
    disable_windowed_traceback=False,
    argv_emulation=True,  # macOS argv emulation for drag-and-drop
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# Collect all files
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AIWhisperer',
)

# Create macOS .app bundle
app = BUNDLE(
    coll,
    name='AIWhisperer.app',
    icon=None,  # Add icon path here if available: str(project_root / 'packaging/macos/resources/icon.icns')
    bundle_identifier='com.aiwhisperer.app',
    version=version,
    info_plist={
        'CFBundleName': 'AIWhisperer',
        'CFBundleDisplayName': 'AIWhisperer',
        'CFBundleGetInfoString': 'Secure document sanitization for AI analysis',
        'CFBundleIdentifier': 'com.aiwhisperer.app',
        'CFBundleVersion': version,
        'CFBundleShortVersionString': version,
        'NSHighResolutionCapable': True,
        'NSRequiresAquaSystemAppearance': False,  # Support dark mode
        'LSMinimumSystemVersion': '10.15',
        'CFBundleDocumentTypes': [
            {
                'CFBundleTypeName': 'PDF Document',
                'CFBundleTypeRole': 'Viewer',
                'LSHandlerRank': 'Alternate',
                'LSItemContentTypes': ['com.adobe.pdf'],
            },
            {
                'CFBundleTypeName': 'Text Document',
                'CFBundleTypeRole': 'Editor',
                'LSHandlerRank': 'Alternate',
                'LSItemContentTypes': ['public.plain-text'],
            },
            {
                'CFBundleTypeName': 'JSON Document',
                'CFBundleTypeRole': 'Editor',
                'LSHandlerRank': 'Alternate',
                'LSItemContentTypes': ['public.json'],
            },
        ],
    },
)
