"""Setup script for DocSanitizer."""
from setuptools import setup, find_packages

setup(
    name="docsanitizer",
    version="0.1.0",
    description="Strip sensitive data from documents for AI analysis",
    author="Public Domain",
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
        "all": [
            "spacy>=3.5.0",
            "presidio-analyzer>=2.2.0",
            "presidio-anonymizer>=2.2.0",
            "gliner>=0.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "docsanitizer=docsanitizer.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
