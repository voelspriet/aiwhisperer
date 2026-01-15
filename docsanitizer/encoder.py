"""
Encoder - Replace sensitive values with placeholders.

The encoder:
1. Detects all sensitive values (names, phones, emails, etc.)
2. Creates consistent placeholders for each unique value
3. Replaces sensitive values while preserving document structure
4. Returns sanitized text + mapping for later decoding

Supports multiple detection backends:
- "hybrid": spaCy NER + patterns combined (recommended, default)
- "patterns": Fast regex-based detection (no dependencies)
- "spacy": spaCy NER only
- "presidio": Microsoft Presidio
- "gliner": GLiNER zero-shot NER

Supports multiple anonymization strategies:
- "replace": Substitute with placeholders (PERSON_001) - reversible
- "redact": Remove completely ([REDACTED])
- "mask": Partial masking (j**@e******.com)
- "hash": One-way hash (a1b2c3d4...)
- "encrypt": Reversible encryption (requires cryptography package)
"""

import re
from typing import Tuple, List, Optional, Union, Literal
from pathlib import Path

from .detectors import detect_all, get_available_backends
from .detectors.patterns import Match
from .mapper import Mapping
from .strategies import get_strategy, AnonymizationStrategy, STRATEGIES

# Type alias for backend selection
Backend = Literal["hybrid", "patterns", "spacy", "presidio", "gliner", "auto"]
Strategy = Literal["replace", "redact", "mask", "hash", "encrypt"]


def _preprocess(text: str) -> Tuple[str, dict]:
    """
    Preprocess text to normalize patterns that span line breaks.

    Returns normalized text and a mapping to restore original formatting.
    """
    # Join lines that break in the middle of a name pattern
    # e.g., "EL\nMANSOURI" -> "EL MANSOURI"
    # We look for: PARTICLE\n + UPPERCASE WORD

    particles = ['EL', 'VAN', 'DE', 'DER', 'DEN', 'TEN', 'TER', 'LA', 'LE']
    for particle in particles:
        # Replace "PARTICLE\nWORD" with "PARTICLE WORD"
        pattern = rf'\b({particle})\n([A-Z][A-Za-z]+)'
        text = re.sub(pattern, r'\1 \2', text)

    return text


def _detect_with_backend(
    text: str,
    backend: Backend = "hybrid",
    language: str = "nl",
    **kwargs
) -> List[Match]:
    """
    Detect sensitive values using the specified backend.

    Args:
        text: Input text
        backend: Detection backend to use
        language: Language code for NER backends
        **kwargs: Additional arguments passed to the detector

    Returns:
        List of Match objects
    """
    if backend == "auto":
        # Use best available backend (hybrid is preferred)
        backends = get_available_backends()
        if backends.get("hybrid"):
            backend = "hybrid"
        elif backends.get("spacy"):
            backend = "spacy"
        else:
            backend = "patterns"

    if backend == "hybrid":
        from .detectors import detect_hybrid, is_hybrid_available
        if not is_hybrid_available():
            # Fallback to patterns if spaCy not installed
            return detect_all(text)
        return detect_hybrid(text, language=language, **kwargs)

    elif backend == "patterns":
        return detect_all(text)

    elif backend == "spacy":
        from .detectors import detect_entities_ner, is_ner_available
        if not is_ner_available():
            raise ImportError("spaCy not installed. Run: pip install spacy")
        return detect_entities_ner(text, language=language, **kwargs)

    elif backend == "presidio":
        from .detectors import detect_with_presidio, is_presidio_available
        if not is_presidio_available():
            raise ImportError("Presidio not installed. Run: pip install presidio-analyzer")
        return detect_with_presidio(text, language=language, **kwargs)

    elif backend == "gliner":
        from .detectors import detect_with_gliner, is_gliner_available
        if not is_gliner_available():
            raise ImportError("GLiNER not installed. Run: pip install gliner")
        return detect_with_gliner(text, **kwargs)

    else:
        raise ValueError(f"Unknown backend: {backend}")


def encode(
    text: str,
    mapping: Optional[Mapping] = None,
    skip_already_masked: bool = True,
    backend: Backend = "hybrid",
    strategy: Strategy = "replace",
    language: str = "nl",
    **kwargs
) -> Tuple[str, Mapping]:
    """
    Encode sensitive values in text with placeholders.

    Args:
        text: Input text containing sensitive data
        mapping: Optional existing mapping (for batch processing)
        skip_already_masked: Skip values containing XX or *** (already masked)
        backend: Detection backend to use:
            - "hybrid": spaCy NER + patterns (default, recommended)
            - "patterns": Fast regex-based (no dependencies)
            - "spacy": spaCy NER only
            - "auto": Use best available
        strategy: Anonymization strategy to use:
            - "replace": Placeholders like PERSON_001 (default, reversible)
            - "redact": Generic markers like [REDACTED]
            - "mask": Partial masking like j**@e******.com
            - "hash": One-way hash like a1b2c3d4
            - "encrypt": Reversible encryption (requires cryptography)
        language: Language code (nl, en, de, fr, it, es)
        **kwargs: Additional arguments passed to the detector

    Returns:
        Tuple of (sanitized_text, mapping)

    Example:
        >>> text = "Jan de Vries woont in Amsterdam"
        >>> sanitized, mapping = encode(text)
        >>> print(sanitized)
        "PERSON_001 woont in PLACE_001"

        # Using mask strategy
        >>> sanitized, _ = encode(text, strategy="mask")

        # Using patterns backend (no spaCy needed)
        >>> sanitized, _ = encode(text, backend="patterns")
    """
    if mapping is None:
        mapping = Mapping()

    # Get the anonymization strategy
    strategy_obj = get_strategy(strategy)

    # Preprocess to handle line breaks in names
    text = _preprocess(text)

    # Detect all sensitive values using selected backend
    matches = _detect_with_backend(text, backend=backend, language=language, **kwargs)

    # Filter out already-masked values
    if skip_already_masked:
        matches = [m for m in matches if not _is_masked(m.text)]

    # Sort matches by position (reverse order for safe replacement)
    matches.sort(key=lambda m: m.start, reverse=True)

    # Apply anonymization strategy to each match
    result = text
    for match in matches:
        if strategy == "replace":
            # Use mapping for consistent placeholders
            anonymized = mapping.get_or_create_placeholder(
                match.text,
                match.category
            )
        else:
            # Use strategy directly
            anon_result = strategy_obj.anonymize(match.text, match.category)
            anonymized = anon_result.anonymized

            # Still track in mapping for reference (even if not reversible)
            mapping.get_or_create_placeholder(match.text, match.category)

        result = result[:match.start] + anonymized + result[match.end:]

    return result, mapping


def generate_legend(mapping: Mapping) -> str:
    """
    Generate a legend explaining placeholders for AI context.

    This helps the AI understand what each placeholder category represents.
    """
    # Category descriptions
    CATEGORY_DESCRIPTIONS = {
        'PERSON': 'Person names (individuals)',
        'PLACE': 'Locations (cities, towns, regions)',
        'STREET': 'Street names',
        'ROAD': 'Road/highway numbers (N-roads, A-roads, E-roads)',
        'VEHICLE': 'Vehicle brands and models (cars, vans, trucks)',
        'ADDRESS': 'Full addresses',
        'PHONE': 'Phone numbers',
        'EMAIL': 'Email addresses',
        'IBAN': 'Bank account numbers',
        'ID': 'National ID numbers (BSN, etc.)',
        'DOB': 'Dates of birth',
        'ORG': 'Organizations',
    }

    # Count placeholders by category
    category_counts = {}
    for placeholder in mapping.entries:
        category = placeholder.rsplit('_', 1)[0]
        category_counts[category] = category_counts.get(category, 0) + 1

    # Build legend
    lines = [
        "=" * 60,
        "DOCUMENT LEGEND - PLACEHOLDER KEY",
        "=" * 60,
        "",
        "This document has been sanitized. Sensitive data has been",
        "replaced with placeholders. Each placeholder follows the",
        "format CATEGORY_NNN (e.g., PERSON_001, PLACE_002).",
        "",
        "PLACEHOLDER CATEGORIES:",
        "",
    ]

    for category, count in sorted(category_counts.items()):
        desc = CATEGORY_DESCRIPTIONS.get(category, 'Other')
        lines.append(f"  {category}_NNN : {desc} ({count} unique)")

    lines.extend([
        "",
        "IMPORTANT: Different numbers = different entities.",
        "  PERSON_001 and PERSON_002 are two different people.",
        "  PLACE_001 appearing twice means the SAME location.",
        "",
        "=" * 60,
        "",
    ])

    return '\n'.join(lines)


def encode_with_legend(
    text: str,
    mapping: Optional[Mapping] = None,
    backend: Backend = "hybrid",
    strategy: Strategy = "replace",
    language: str = "nl",
    **kwargs
) -> Tuple[str, Mapping]:
    """
    Encode text and prepend a legend explaining placeholders.

    This is recommended when sending to AI for analysis, as the legend
    helps the AI understand what each placeholder category represents.
    """
    sanitized, mapping = encode(
        text,
        mapping=mapping,
        backend=backend,
        strategy=strategy,
        language=language,
        **kwargs
    )

    legend = generate_legend(mapping)
    return legend + sanitized, mapping


def encode_file(
    input_path: Union[str, Path],
    backend: Backend = "patterns",
    language: str = "nl",
    output_path: Optional[Union[str, Path]] = None,
    mapping_path: Optional[Union[str, Path]] = None,
    encoding: str = 'utf-8'
) -> Tuple[str, Mapping]:
    """
    Encode a file and optionally save results.

    Args:
        input_path: Path to input file
        backend: Detection backend (patterns, spacy, presidio, gliner, auto)
        language: Language code for NER backends
        output_path: Path for sanitized output (optional)
        mapping_path: Path for mapping JSON (optional)
        encoding: File encoding (default utf-8)

    Returns:
        Tuple of (sanitized_text, mapping)
    """
    input_path = Path(input_path)

    # Read input
    with open(input_path, 'r', encoding=encoding) as f:
        text = f.read()

    # Encode with selected backend
    sanitized, mapping = encode(text, backend=backend, language=language)

    # Save outputs if paths provided
    if output_path:
        with open(output_path, 'w', encoding=encoding) as f:
            f.write(sanitized)

    if mapping_path:
        mapping.save(mapping_path)

    return sanitized, mapping


def _is_masked(text: str) -> bool:
    """Check if a value is already masked (contains XX or ***)."""
    return 'XX' in text or 'xx' in text or '***' in text or 'XXX' in text


def get_statistics(mapping: Mapping) -> dict:
    """Get statistics about the encoding."""
    stats = {
        "total_unique_values": len(mapping.entries),
        "total_occurrences": sum(e.occurrences for e in mapping.entries.values()),
        "by_category": {},
    }

    for placeholder, entry in mapping.entries.items():
        category = placeholder.rsplit('_', 1)[0]
        if category not in stats["by_category"]:
            stats["by_category"][category] = {
                "unique": 0,
                "occurrences": 0,
                "examples": []
            }
        stats["by_category"][category]["unique"] += 1
        stats["by_category"][category]["occurrences"] += entry.occurrences
        if len(stats["by_category"][category]["examples"]) < 3:
            stats["by_category"][category]["examples"].append(
                f"{placeholder} → {entry.canonical[:30]}..."
                if len(entry.canonical) > 30 else
                f"{placeholder} → {entry.canonical}"
            )

    return stats
