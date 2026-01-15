#!/usr/bin/env python3
"""
Download spaCy language models for NER detection.

Usage:
    python download_models.py           # Download all models
    python download_models.py nl en     # Download specific models
    python download_models.py --check   # Check which models are installed
"""

import subprocess
import sys
from typing import List, Optional

LANGUAGE_MODELS = {
    'nl': ('nl_core_news_sm', 'Dutch'),
    'en': ('en_core_web_sm', 'English'),
    'de': ('de_core_news_sm', 'German'),
    'fr': ('fr_core_news_sm', 'French'),
    'it': ('it_core_news_sm', 'Italian'),
    'es': ('es_core_news_sm', 'Spanish'),
}


def check_spacy_installed() -> bool:
    """Check if spaCy is installed."""
    try:
        import spacy
        return True
    except ImportError:
        return False


def check_model_installed(model_name: str) -> bool:
    """Check if a specific model is installed."""
    try:
        import spacy
        spacy.load(model_name)
        return True
    except (ImportError, OSError):
        return False


def download_model(model_name: str) -> bool:
    """Download a spaCy model."""
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'spacy', 'download', model_name],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Error downloading {model_name}: {e}")
        return False


def check_status():
    """Print status of all language models."""
    print("\n=== spaCy Language Model Status ===\n")

    if not check_spacy_installed():
        print("spaCy is NOT installed.")
        print("Install with: pip install spacy\n")
        return

    print("spaCy is installed.\n")
    print(f"{'Language':<12} {'Code':<6} {'Model':<20} {'Status':<12}")
    print("-" * 55)

    for code, (model, lang_name) in LANGUAGE_MODELS.items():
        installed = check_model_installed(model)
        status = "Installed" if installed else "Not installed"
        print(f"{lang_name:<12} {code:<6} {model:<20} {status:<12}")

    print()


def download_models(languages: Optional[List[str]] = None):
    """Download specified or all language models."""
    if not check_spacy_installed():
        print("spaCy is not installed. Installing...")
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', 'spacy'],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print("Failed to install spaCy. Please install manually:")
            print("  pip install spacy")
            return

    if languages is None:
        languages = list(LANGUAGE_MODELS.keys())

    print(f"\nDownloading {len(languages)} language model(s)...\n")

    success = []
    failed = []

    for lang in languages:
        if lang not in LANGUAGE_MODELS:
            print(f"Unknown language: {lang}")
            failed.append(lang)
            continue

        model, lang_name = LANGUAGE_MODELS[lang]

        if check_model_installed(model):
            print(f"[OK] {lang_name} ({model}) - already installed")
            success.append(lang)
            continue

        print(f"[..] Downloading {lang_name} ({model})...", end=" ", flush=True)
        if download_model(model):
            print("OK")
            success.append(lang)
        else:
            print("FAILED")
            failed.append(lang)

    print(f"\n=== Summary ===")
    print(f"Installed: {len(success)}/{len(languages)}")
    if failed:
        print(f"Failed: {', '.join(failed)}")
    print()


def main():
    args = sys.argv[1:]

    if '--help' in args or '-h' in args:
        print(__doc__)
        print("Available languages:")
        for code, (model, name) in LANGUAGE_MODELS.items():
            print(f"  {code}: {name} ({model})")
        return

    if '--check' in args:
        check_status()
        return

    if args:
        # Download specific languages
        languages = [arg.lower() for arg in args]
        download_models(languages)
    else:
        # Download all languages
        download_models()


if __name__ == '__main__':
    main()
