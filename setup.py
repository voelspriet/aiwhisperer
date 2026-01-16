"""Setup script for AIWhisperer."""
from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme = Path(__file__).parent / "README.md"
long_description = readme.read_text(encoding="utf-8") if readme.exists() else ""

setup(
    name="aiwhisperer",
    version="0.5.0",
    description="Shrink massive PDFs to fit AI upload limits. Sanitize before uploading to reduce risk of exposing sensitive data.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Henk van Ess",
    url="https://github.com/voelspriet/aiwhisperer",
    project_urls={
        "Documentation": "https://github.com/voelspriet/aiwhisperer#readme",
        "Source": "https://github.com/voelspriet/aiwhisperer",
        "Issues": "https://github.com/voelspriet/aiwhisperer/issues",
    },
    license="CC0-1.0",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0.0",
    ],
    extras_require={
        "dev": ["pytest"],
        "spacy": ["spacy>=3.5.0"],
        "presidio": ["presidio-analyzer>=2.2.0", "presidio-anonymizer>=2.2.0"],
        "gliner": ["gliner>=0.2.0"],
        "ocr": ["marker-pdf"],
        "ocr-fallback": ["pymupdf>=1.23.0", "pytesseract>=0.3.10", "pdf2image>=1.16.0"],
        "all": [
            "spacy>=3.5.0",
            "presidio-analyzer>=2.2.0",
            "presidio-anonymizer>=2.2.0",
            "gliner>=0.2.0",
            "marker-pdf",
        ],
    },
    entry_points={
        "console_scripts": [
            "aiwhisperer=aiwhisperer.cli:main",
        ],
    },
    keywords=[
        "ai", "llm", "pdf", "ocr", "anonymization", "pii", "privacy",
        "nlp", "ner", "chatgpt", "claude", "gemini", "notebooklm",
        "document-processing", "osint", "investigation"
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Legal Industry",
        "Intended Audience :: Science/Research",
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Text Processing",
        "Topic :: Security",
    ],
)
