"""
AIWhisperer - Complete pipeline for AI analysis of confidential documents.

Whisper your documents to AI without exposing sensitive data.
Supports 6 languages: Dutch, English, German, French, Italian, Spanish.

Usage:
    from aiwhisperer import encode, decode

    # Encode document (replaces PII with placeholders)
    sanitized, mapping = encode(text, language='nl')

    # ... send sanitized to AI ...

    # Decode AI output back to original values
    result = decode(ai_output, mapping)

Detection backends:
    - "hybrid" (default): spaCy NER + patterns (requires spaCy)
    - "patterns": Regex-based only (no dependencies)

Anonymization strategies:
    - "replace" (default): Reversible placeholders (PERSON_001)
    - "redact": Generic markers ([REDACTED])
    - "mask": Partial masking (j**@e******.com)
    - "hash": One-way hash
"""

__version__ = "0.5.0"

from .encoder import encode, get_statistics
from .decoder import decode
from .mapper import Mapping

__all__ = ["encode", "decode", "Mapping", "get_statistics"]
