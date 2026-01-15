"""
PII detectors for sensitive data.

Three detection methods are available:
1. Hybrid (recommended) - combines spaCy NER + patterns for best results
2. Pattern-based (regex) - fast, no dependencies
3. NER-based (spaCy only) - for names/locations

The hybrid detector is recommended for production use.
"""

from .patterns import (
    detect_all,
    detect_phones,
    detect_emails,
    detect_ibans,
    detect_addresses,
    detect_streets,
    detect_places,
    detect_dates_of_birth,
    detect_names,
    detect_national_ids,
    Match,
)

# =============================================================================
# Hybrid detector (recommended) - spaCy NER + patterns
# =============================================================================
try:
    from .hybrid import (
        HybridDetector,
        detect_hybrid,
        get_hybrid_detector,
    )
    _HYBRID_AVAILABLE = True
except ImportError:
    _HYBRID_AVAILABLE = False
    HybridDetector = None

    def detect_hybrid(*args, **kwargs):
        raise ImportError("spaCy not installed. Run: pip install spacy")

    def get_hybrid_detector():
        raise ImportError("spaCy not installed. Run: pip install spacy")


# =============================================================================
# spaCy NER imports (optional)
# =============================================================================
try:
    from .ner import (
        NERDetector,
        detect_entities_ner,
        is_ner_available,
        get_available_languages,
        get_detector as get_ner_detector,
    )
    _SPACY_AVAILABLE = True
except ImportError:
    _SPACY_AVAILABLE = False
    NERDetector = None

    def detect_entities_ner(*args, **kwargs):
        raise ImportError("spaCy not installed. Run: pip install spacy")

    def is_ner_available():
        return False

    def get_available_languages():
        return []

    def get_ner_detector():
        raise ImportError("spaCy not installed. Run: pip install spacy")


# =============================================================================
# Presidio imports (optional)
# =============================================================================
try:
    from .presidio_detector import (
        PresidioDetector,
        detect_with_presidio,
        is_presidio_available,
        get_presidio_detector,
    )
    _PRESIDIO_AVAILABLE = True
except ImportError:
    _PRESIDIO_AVAILABLE = False
    PresidioDetector = None

    def detect_with_presidio(*args, **kwargs):
        raise ImportError("Presidio not installed. Run: pip install presidio-analyzer")

    def is_presidio_available():
        return False

    def get_presidio_detector():
        raise ImportError("Presidio not installed. Run: pip install presidio-analyzer")


# =============================================================================
# GLiNER imports (optional)
# =============================================================================
try:
    from .gliner_detector import (
        GLiNERDetector,
        detect_with_gliner,
        is_gliner_available,
        get_gliner_detector,
        DEFAULT_PII_LABELS,
        EXTENDED_PII_LABELS,
    )
    _GLINER_AVAILABLE = True
except ImportError:
    _GLINER_AVAILABLE = False
    GLiNERDetector = None
    DEFAULT_PII_LABELS = []
    EXTENDED_PII_LABELS = []

    def detect_with_gliner(*args, **kwargs):
        raise ImportError("GLiNER not installed. Run: pip install gliner")

    def is_gliner_available():
        return False

    def get_gliner_detector():
        raise ImportError("GLiNER not installed. Run: pip install gliner")


def is_hybrid_available() -> bool:
    """Check if hybrid detector is available (requires spaCy)."""
    return _HYBRID_AVAILABLE and _SPACY_AVAILABLE


def get_available_backends() -> dict:
    """Get status of all detection backends."""
    return {
        "hybrid": is_hybrid_available(),  # Recommended
        "patterns": True,  # Always available (regex-based)
        "spacy": is_ner_available(),
        "presidio": is_presidio_available(),
        "gliner": is_gliner_available(),
    }


__all__ = [
    # Hybrid detector (recommended)
    "detect_hybrid",
    "HybridDetector",
    "get_hybrid_detector",
    "is_hybrid_available",
    # Pattern-based detectors
    "detect_all",
    "detect_phones",
    "detect_emails",
    "detect_ibans",
    "detect_addresses",
    "detect_streets",
    "detect_places",
    "detect_dates_of_birth",
    "detect_names",
    "detect_national_ids",
    "Match",
    # spaCy NER
    "NERDetector",
    "detect_entities_ner",
    "is_ner_available",
    "get_available_languages",
    "get_ner_detector",
    # Presidio
    "PresidioDetector",
    "detect_with_presidio",
    "is_presidio_available",
    "get_presidio_detector",
    # GLiNER
    "GLiNERDetector",
    "detect_with_gliner",
    "is_gliner_available",
    "get_gliner_detector",
    "DEFAULT_PII_LABELS",
    "EXTENDED_PII_LABELS",
    # Utilities
    "get_available_backends",
]
